import sys
import logging

# required before other imports (yes; see: https://stackoverflow.com/a/20280587)
# logging.basicConfig(
#     format='%(message)s',
#     level=logging.DEBUG, # use logging.INFO to only print LaTeX
#     stream=sys.stdout
# )

import json
import numpy as np
import pandas as pd
from collections import Counter

from sklearn.model_selection import train_test_split


def read_conf(filename): 
    """
    Read a JSON file
    """
    with open(filename, 'r') as jf:
        return json.load(jf)


class Dataset(object):
    """
    Helper class to retrieve a dataset from a CSV file
    because passing everything as parameters was tiring 
    """
    def __init__(
            self, 
            filename: str, 
            label_column: str, 
            selected_columns: list[str], 
            excluded_columns: list[str], 
            selected_rows: list[str], 
            nrows: int, 
            random_state: int
        ):
        self.filename = filename
        self.label_column = label_column
        self.selected_columns = selected_columns
        self.excluded_columns = excluded_columns
        self.selected_rows = selected_rows
        self.nrows = nrows
        self.random_state = random_state 

    def load_data_from_csv(self):
        logging.debug(f"[-] Getting features from the following csv: {self.filename}")

        cols = list(pd.read_csv(self.filename, nrows=1))
        usecols = cols
    
        if len(self.selected_columns) > 0 and self.selected_columns[0] != "": 
            usecols = self.selected_columns 
        
        if len(self.excluded_columns) > 0 and self.excluded_columns[0] != "": 
            usecols =[i for i in usecols if i not in self.excluded_columns]
        
        # if the use forgot (skull emoji) to select the label column, we happily add it to the mix :)
        if self.label_column not in usecols: 
            usecols.append(self.label_column)

        self.data = pd.read_csv(
            self.filename,
            usecols=usecols,
            dtype={'dutycycleDiff': 'O'},
            nrows=self.nrows,
            low_memory=False,
        )

    def load_dataset_from_csv(self):
        self.load_data_from_csv()
        # only keeping the rows we're interested in
        if len(self.selected_rows) != 0: 
            self.data = self.data[self.data.y.isin(self.selected_rows)]

        dataset = self.data.values
        self.X = dataset[:,1:].astype(float)
        self.input_dimensions = self.X.shape[1]
        self.y = dataset[:,0]
        self.nb_labels = len(set(self.y))    
        
        self.y = np.array(self.data[self.label_column])

        self.X = self.data.drop(self.label_column, axis=1) # axis 1 refers to the columns
        self.column_names = self.X.columns
        self.X = np.array(self.X)

    def prepare_data(self):
        # Getting data from the csv file
        self.load_dataset_from_csv()

        # 80/20 split for the whole dataset, keeping the 20% as held-out data 
        try: 
            """
            Keeping the same proportion of classes by using stratify 
            Note: this was added because *sometimes*, the train_test_split function
            would create training/testing sets with missing under-represented classes
            This happens *before* resampling so it would go on and crash when using 
            neural networks.
            Under-represented classes are caused by IoT devices not communicating often
            (eg: less than 10 times, see lepro_light)
            """
            self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
                self.X,
                self.y,
                test_size=0.2,
                random_state=self.random_state,
                stratify=self.y,
            )
        except ValueError as err:
            logging.error(f"[ValueError] {self.filename}")
            print(err)
            raise 

    def print_dataset_info(self): 
        logging.debug(f"\n[+] New dataset:")
        logging.debug(f"Training Features Shape: {self.X_train.shape}")
        logging.debug(f"Training Labels Shape: {self.y_train.shape} ({len(set(self.y_train))})")
        logging.debug(f"Testing Features Shape: {self.X_test.shape}")
        logging.debug(f"Testing Labels Shape: {self.y_test.shape} ({len(set(self.y_test))})")


def prepare_columns_dns_str(all_columns: list, extract_config) -> dict: 
    """
    Separating columns based on the number of unique DNS qname encountered 
    during the extraction process and saved in the extract_config
    """
    ordered_columns = {
        "dns_str": {}
    }
    prev = 0 
    for qt, val in extract_config["qname_types"].items(): 
        ordered_columns["dns_str"][qt] = all_columns[prev:prev+val]
        prev = prev+val 
    return ordered_columns


def check_last_stats(col_name: str, key: int, max_nb_query: int)-> bool:
    """
    Returns true if the col_name is the correct statisitical aggregate 
    (aka the last one) *or* true if it's any other thing
    """ 
    ok = False 
    if "stats" in col_name:
        if key == max_nb_query-1: 
            ok = True
    else: 
        ok = True
    return ok 


def prepare_columns(all_columns: list, extract_config: dict, resolvers_config: dict, is_dns_str: bool=False) -> dict: 
    if is_dns_str: 
        return prepare_columns_dns_str(all_columns, extract_config)
    
    """
    Separating columns based on their roles 
    Column name format (see PcapExtract): 
    {resolver}-{time_window}-{col_name}-{nb_msg}
    {resolver}-{time_window}-{col_name}-{stat}-{nb_msg}

    Eg: 
    NOT_A_RESOLVER-2-columns_iat-14
    dot_AdGuard-300-stats_padding_no_padding_both-skewness-21
    dot_AdGuard-180-stats_padding_random_block_down-std-6
    """
    ordered_columns = {}

    # Preparing ordered_columns
    for resolver_type in resolvers_config['resolvers']: 
        for resolver_obj in resolvers_config['resolvers'][resolver_type]:
            resolver = f"{resolver_type}_{resolver_obj['name']}"
            ordered_columns[resolver] = {
                "all_both": [], # absolutely everything (no_padding, all time windows)
                "all_up": [], # only up (device -> server) (no_padding, all time windows)
                "all_down": [], # only down (server -> device) (no_padding, all time windows)
                "iat_only": [], # only iat-based features (all time windows)
                "by_time": {}, # everything, but excluding features that are not based on the same time window
                "by_number": {}, # everything, but when looking at numbers of messages, it's only *up to* said number
            }

            for padding_strat in resolvers_config['padding_strategies']: 
                # only length-based features
                ordered_columns[resolver][f"{padding_strat}_both"] = []
                ordered_columns[resolver][f"{padding_strat}_up"] = []
                ordered_columns[resolver][f"{padding_strat}_down"] = []

            for i in range(extract_config['max_nb_query']): 
                ordered_columns[resolver]["by_number"][i] = [] 

    for col in all_columns: 
        s = col.split("-")
        resolver = s[0]
        time_window = s[1]
        col_name = s[2]
        nb_msg = int(s[-1])

        if "both" in col_name or "up" in col_name or "down" in col_name: 
            direction = col_name.split("_")[-1]
        
        if resolver == "ALL_RESOLVERS": 
            # This column is relevant to *all* resolvers.
            # It is IAT-based
            for resolver_col in ordered_columns: 
                if time_window not in ordered_columns[resolver_col]["by_time"]: 
                    ordered_columns[resolver_col]["by_time"][time_window] = []
                # By default, we're interested in the last value of the stats (maximum number of msgs)
                # Adding...
                if check_last_stats(col_name, nb_msg, extract_config['max_nb_query']):
                    ordered_columns[resolver_col][f"all_both"].append(col)
                    ordered_columns[resolver_col][f"all_up"].append(col)
                    ordered_columns[resolver_col][f"all_down"].append(col)
                    ordered_columns[resolver_col]["iat_only"].append(col)
                    # to the specific time window (makes sense to add only the best stat here)
                    ordered_columns[resolver_col]["by_time"][time_window].append(col)
                if "stats" in col_name: 
                    for i in range(extract_config['max_nb_query']): 
                        if i == nb_msg: 
                            ordered_columns[resolver_col]["by_number"][i].append(col)
                else: 
                    for i in range(extract_config['max_nb_query']): 
                        if nb_msg <= i: 
                            ordered_columns[resolver_col]["by_number"][i].append(col)
        else:
            # at this point, we're NOT dealing with IAT values, but only length based ones
            if resolver not in ordered_columns: 
                logging.error(f"[ValueError] Unkown resolver: {resolver}")
                raise ValueError
            if time_window not in ordered_columns[resolver]["by_time"]: 
                ordered_columns[resolver]["by_time"][time_window] = []
            # There are 2 cases: either we limit the number of msg studied (eg: only the first 20 msg)
            # or we don't. If we do not....
            if check_last_stats(col_name, nb_msg, extract_config['max_nb_query']):
                # all_* is based on the no_padding strategy (default)
                if "no_padding" in col_name: 
                    ordered_columns[resolver][f"all_{direction}"].append(col)
                    if "both" in col_name: 
                        # by_time is constructed only using default padding strat (no_padding)
                        # and the "both" direction 
                        ordered_columns[resolver]["by_time"][time_window].append(col)
                # Using only the length-based features to evaluate padding strategies
                if "padding" in col_name:
                    # Using the padding strategy as name (it contains the direction still)
                    padding_strat = col_name.replace("columns_", "").replace("stats_", "")
                    ordered_columns[resolver][f"{padding_strat}"].append(col)
            # If we *do* limit the number of messages... 
            # We want to keep up to the correct number of messages
            # and the exact correct number for stats (ie: up to 20 msg, and stats-19)
            # by_number is based on the no_padding strategy and the "both" direction
            if "no_padding" in col_name and "both" in col_name: 
                if "stats" in col_name: 
                    for i in range(extract_config['max_nb_query']): 
                        if i == nb_msg: 
                            ordered_columns[resolver]["by_number"][i].append(col)
                else: 
                # Add the columns *up to* the number. For example: 
                # dot_8.8.8.8-300-columns_iat-21 corresponds to the 21th value of IAT
                # we want to add it to [<25], [<30], but not [<10] queries
                # NOTE: there are more values for the length than for the IAT, take it into account
                    for i in range(extract_config['max_nb_query']): 
                        if nb_msg <= i * extract_config["length_multiplier"] + 1: 
                            ordered_columns[resolver]["by_number"][i].append(col)
    
    # print(ordered_columns['dot_Cloudflare']['all_both'])
    # print(ordered_columns['dot_Cloudflare']['iat_only'])
    # print(ordered_columns['dot_Cloudflare']['padding_random_block_up'])
    # print(ordered_columns['dot_Cloudflare']['by_number'][0])
    # print(ordered_columns['dot_Cloudflare']['by_time']["5"])
    return ordered_columns

