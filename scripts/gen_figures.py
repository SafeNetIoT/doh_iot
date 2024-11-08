#!/usr/bin/env python3


import glob 
import json
import os.path 
import argparse 
import numpy as np 
import pandas as pd

from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt

import seaborn as sns
sns.set_style("ticks")
# sns.color_palette("mako", as_cmap=True)
sns.color_palette("flare", as_cmap=True)
sns.set_style("whitegrid")
plt.rcParams["font.family"] = "serif"

SMALL_SIZE = 15
MEDIUM_SIZE = 20
BIGGER_SIZE = 30

plt.rc('font', size=MEDIUM_SIZE)          # controls default text sizes
plt.rc('axes', titlesize=MEDIUM_SIZE)     # fontsize of the axes title
plt.rc('axes', labelsize=MEDIUM_SIZE)    # fontsize of the x and y labels
plt.rc('xtick', labelsize=MEDIUM_SIZE)    # fontsize of the tick labels
plt.rc('ytick', labelsize=MEDIUM_SIZE)    # fontsize of the tick labels
plt.rc('legend', fontsize=MEDIUM_SIZE)    # legend fontsize
plt.rc('figure', titlesize=BIGGER_SIZE)  # fontsize of the figure title



def draw(name: str): 
    figure = plt.gcf()  # get current figure
    # figure.set_size_inches(22, 16)
    figure.set_size_inches(16, 10)

    # figure.set_size_inches(16, 7) # set figure's size manually to your full screen (32x18)
    if name != "":
        plt.savefig(name, bbox_inches="tight", dpi = 300)
    plt.show()


def get_value_from_file(file, score): 
    with open(file) as f: 
        json_data = json.load(f)
        return json_data[score]

def find_equivalent_value(compare_path: str, initial_filepath: str, score: str): 
    """
    Maybe another classifier was selected in the compared run. 
    Which means we can *not* use exactly the same filename. 
    If that's the case, we need to find `?????-<resolver>-<mode>-<seed>.json` using glob
    """
    print("--------")
    print(f"Initial file path: {initial_filepath}")
    print(f"Relative compare path: {compare_path}")

    initial_filename = initial_filepath.split('/')[-1]
    base_path = '/'.join(initial_filepath.split('/')[:-1])

    exact_filepath = f"{base_path}/{compare_path}{initial_filename}" # without the filename
    print(f"Exact filepath: {exact_filepath}")
    if os.path.isfile(exact_filepath):
        return get_value_from_file(exact_filepath, score)
    else: 
        print("[!] Exact file not found; looking for another classifier")
        initial_split_by_dash = initial_filename.split('-')
        initial_filename_without_classifier = '-'.join(initial_split_by_dash[1:])
        glob_path = f"{base_path}/{compare_path}/*-{initial_filename_without_classifier}"
        corresponding_files = glob.glob(glob_path)
        if len(corresponding_files) != 1: 
            print(f"More or less than one match for glob path: {glob_path}")
            print(corresponding_files)
            return None 
        print(f"Corresponding file: {corresponding_files[0]}")
        return get_value_from_file(corresponding_files[0], score)


def get_results(files: list[str], score: str, compare_path: str, run_id: str="0") -> dict: 
    """
    Each file contains the results for:
    - a single resolver
    - a single mode 
    eg: 
    RandomForestClassifier-dot_8.8.8.8-padding_random_block-20.json
    RandomForestClassifier-dot_1.1.1.1-by_time_5-16.json

    Using a compare path: 
    <initial_path><relative_compare_path><filename>
    """
    res = {
        "run_id": [],
        "classifier": [],
        "resolver": [],
        "mode_": [], # mode is already used by Pandas https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.mode.html
        "val": [],
        "confusion_matrix": [],
    }
    import time 
    import datetime 
    class_lengths = {}
    for f in files: 
        if os.path.isfile(f):
            t = os.path.getmtime(f)
            d = datetime.datetime.fromtimestamp(t)
            if d > datetime.datetime(2023, 11, 27): 
                with open(f) as fp: 
                    filename = f.split('/')[-1]
                    split_by_dash = filename.split('-')
                    seed = int(split_by_dash[-1].replace(".json", ""))
                    json_data = json.load(fp) 
                    l = len(json_data['classification_report'])
                    if l not in class_lengths: 
                        class_lengths[l] = 1 
                    else: 
                        class_lengths[l] += 1
                    val = json_data[score]

                    if compare_path: 
                        compare_val = find_equivalent_value(compare_path, f, score)
                        if compare_val: 
                            val = val - compare_val
                        else: 
                            val = None 
                    if val != None: 
                        res['run_id'].append(run_id)
                        res['val'].append(val)
                        res['classifier'].append(split_by_dash[0])
                        res['resolver'].append(split_by_dash[1])
                        res['mode_'].append(split_by_dash[2])
                        if "confusion_matrix" in json_data:
                            res['confusion_matrix'].append(json_data['confusion_matrix'])
    if len(res["confusion_matrix"]) != len(res["run_id"]): 
        del res["confusion_matrix"]
    return res 


def compare_run_helper(
        name: str, 
        data, 
        order: list, 
        xtickslabels: list,
        hue_order: list, 
        legend_labels: list, 
        xlabel: str, 
        ylabel: str,
    ):

    ax = sns.boxplot(
        data=data, 
        x="resolver", 
        y="val", 
        hue="mode_",
        hue_order=hue_order,
        order=order,
        palette="colorblind"
    )
    # adding separators around the resolvers
    # yes, this is ugly. but deadline approching. yes.  
    ax.axvline(x=-0.5, color="grey", alpha=0.3)
    ax.axvline(x=0.5, color="grey", alpha=0.3)
    ax.axvline(x=1.5, color="grey", alpha=0.3)
    ax.axvline(x=2.5, color="grey", alpha=0.3)
    ax.axvline(x=3.5, color="grey", alpha=0.3)
    ax.axvline(x=4.5, color="grey", alpha=0.3)

    medians = data.groupby(['resolver'])['val'].median()
    print(medians.sort_values(ascending=False).to_latex())

    medians = data.groupby(['mode_'])['val'].median()
    print(medians.sort_values(ascending=False).to_latex())

    hatches = ['//', '..', 'xx', '||', '\\\\']
    patches = [patch for patch in ax.patches if type(patch) == mpl.patches.PathPatch]
    # the number of patches should be evenly divisible by the number of hatches
    h = hatches[:4] * 6 
    # iterate through the patches for each subplot
    for patch, hatch in zip(patches, h):
        patch.set_hatch(hatch)
        fc = patch.get_facecolor()
        patch.set_edgecolor(fc)
        patch.set_facecolor('none')

    leg = ax.get_legend()
    new_title = ''
    leg.set_title(new_title)
    for t, l in zip(leg.texts, legend_labels):
        t.set_text(l)

    for lp, hatch in zip(leg.get_patches(), hatches):
        lp.set_hatch(hatch)
        fc = lp.get_facecolor()
        lp.set_edgecolor(fc)
        lp.set_facecolor('none')


    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    sns.move_legend(ax, "lower center", bbox_to_anchor=(0.5, 1), ncols=2)
    # sns.move_legend(ax, "lower right")
    ax.set_xticklabels(xtickslabels)
    ax.set_ylim(0.5, 1)



    draw(name)


def solo_run_helper(name, data, column_keyword: str, xlabel: str, ylabel: str, sns_callback=sns.boxplot): 
    """
    "Time window (in seconds)"
    """
    df = data[data.mode_.str.contains(column_keyword)]
    df["mode_"] = df["mode_"].apply(lambda x: int(x.replace(column_keyword, "")))
    if column_keyword == "by_number_":
        # to make sure the x axis is labelled correctly (no "0 message")
        df["mode_"] += 1
    sns.color_palette("mako", as_cmap=True)
    ax = sns_callback(
        data=df, 
        x="mode_", 
        y="val", 
        # hue="resolver",
        color="cadetblue",
    )

    plt.grid(visible=True)
    ax.set_ylim(0.5, 1)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.legend(title='')

    draw(name)

def read_conf(filename): 
    """
    Read a JSON file
    """
    with open(filename, 'r') as jf:
        return json.load(jf)


def swtich_diagonal_values(matrix, devices_list, device1, device2):
    i_dev1 = devices_list.index(device1)
    i_dev2 = devices_list.index(device2)
    switch_place(matrix, i_dev1, i_dev1, i_dev2, i_dev2)

def switch_place(m, x1, y1, x2, y2): 
    """
    Switches (x1, y2) with (x2, y2) in a 2D matrix
    """
    tmp = m[x1][y1]
    m[x1][y1] = m[x2][y2]
    m[x2][y2] = tmp


if __name__ == "__main__":
    """
    - compute the median for all the results 
    - display in tables / graphs
    """
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('--score', '-s', help='What kind of score are studying (default: balanced accuracy)', default="balanced_accuracy")
    parser.add_argument('--figures', '-f', help="Generate figures or specific list of ids (eg: '11,14,15')", default="everything")
    parser.add_argument('--input_path', '-i', help="Glob path  where all the results lie", default="./data/results/*")
    parser.add_argument('--compare_path', '-c', help="Glob path where other results must be compared", default="")
    parser.add_argument('--resolvers_config', '-rc', help='Config file containing stable parameters used for resovlers', required=True)

    parser.add_argument('--output_path', '-o', help="Where to save the figures", default="./figures/")
    parser.add_argument('--extension', '-e', help="The figures' format (default: pdf, can use png)", default="pdf")
    
    parser.add_argument('--devices_config', '-dc', help='The JSON configuration file with devices names used to train the loaded model')
    
    parser.add_argument('--doh_only', '-doh', help='Only use DoH (excludes DoT)', action=argparse.BooleanOptionalAction)
    parser.add_argument('--resolver_only', '-r', help='Only use the specified resolver', default="")
    parser.add_argument('--direction', '-dir', help='Up, down, both?', default="both")

    args = parser.parse_args()
    figures = args.figures.split(",")
    extension = args.extension
    score = args.score 

    files = glob.glob(args.input_path) 
    
    data = pd.DataFrame(get_results(files, score, ""))
    data = data.reset_index(drop=True)
    if args.doh_only: 
        data = data.loc[data.resolver.str.contains("doh")]
    data = data.loc[data.resolver.str.contains(args.resolver_only)]

    score_str = score.replace("_", " ").capitalize()
    base_output_path = f"{args.output_path}/"
    Path(base_output_path).mkdir(parents=True, exist_ok=True)

    base_output_path = f"{base_output_path}results-{score}-" 

    reference_mode = "all"

    resolvers_config = read_conf(args.resolvers_config)
    resolvers_names = []
    resolvers_names_pretty = []
    for resolver_type in resolvers_config['resolvers']:
        for resolver_obj in resolvers_config['resolvers'][resolver_type]:
            if args.doh_only:
                if resolver_type == "doh": 
                    resolvers_names.append(f"{resolver_type}_{resolver_obj['name']}")
                    resolvers_names_pretty.append(resolver_obj['name'])
            else: 
                resolvers_names.append(f"{resolver_type}_{resolver_obj['name']}")
                resolvers_names_pretty.append(f"{resolver_obj['name']} ({resolver_type})")


    if "everything" in figures or "confusion" in figures: 
        import matplotlib.pyplot as plt
        from sklearn.metrics import ConfusionMatrixDisplay
        print(data)
        res_matrix = None
        rows_sum = None 

        nb_matrices = 0
        for index, row in data.iterrows():
            if res_matrix == None: 
                res_matrix = [0] * len(row['confusion_matrix'])
                rows_sum = [0] * len(row['confusion_matrix'])
                for i in range(len(row['confusion_matrix'])): 
                    res_matrix[i] = [0] * len(row['confusion_matrix'][i])
                    rows_sum[i] += np.sum(row['confusion_matrix'][i])
                    for j in range(len(row['confusion_matrix'][i])):
                        res_matrix[i][j] = row['confusion_matrix'][i][j]
            else: 
                for i in range(len(row['confusion_matrix'])):
                    rows_sum[i] += np.sum(row['confusion_matrix'][i])
                    for j in range(len(row['confusion_matrix'][i])):
                        res_matrix[i][j] += row['confusion_matrix'][i][j]
            nb_matrices += 1 
        round_val = 1
        # normalization 
        for i in range(len(row['confusion_matrix'])): 
            for j in range(len(row['confusion_matrix'][i])):
                res_matrix[i][j] = round(res_matrix[i][j] / rows_sum[i], round_val)

        # this is the list of devices unordered alphabetically 
        # but it corresponds to the correct lines in the matrix
        devices_list = [
            "Alexa Swan Kettle",
            "Aqara HubM2",
            "Arlo Camera Pro4",
            "Blink Mini Camera",
            "Boifun Baby",
            "Bose Speaker",
            "Coffee Maker Lavazza",
            "Cosori Air Fryer",
            "Echodot4",
            "Echodot5",
            "Eufy Chime",
            "Furbo Dog Camera",
            "Google Nest Doorbell",
            "Google Nest Hub",
            "Govee Strip Light",
            "Homepod",
            "Lepro Bulb",
            "Lifx Mini",
            "Meross Garage Door",
            "Nanoleaf Triangles",
            "Google Nest Camera", # bad boi. 
            "Netatmo Weather Station",
            "Petsafe Feeder",
            "Reolink Doorbell",
            "Ring Chime Pro",
            "Sensibo Sky Sensor",
            "Simplicam",
            "Sonos Speaker",
            "Tapo Plug",
            "Vtech Baby Camera",
            "Withings Sleep Analyser",
            "Wiz Bulb",
            "Wyze Cam Pan v2",
            "Yeelight Bulb"
        ]
        
        """
        "Google Nest Camera" is not alphabetically ordered, so we need to put in the right place
        it just happens to be right in the middle, where there only values in the diagonal and not on the side
        so we progressively shift all the diagonal values
        """
        to_switch_devices = [
            "Google Nest Doorbell",
            "Google Nest Hub",
            "Govee Strip Light",
            "Homepod",
            "Lepro Bulb",
            "Lifx Mini",
            "Meross Garage Door",
            "Nanoleaf Triangles"
        ]
        for tsd in to_switch_devices: 
            swtich_diagonal_values(res_matrix, devices_list, "Google Nest Camera", tsd)

        devices_list = sorted(devices_list) # alphabetical sort just for google nest camera
        df_cm = pd.DataFrame(res_matrix, index = [i for i in devices_list],
                  columns = [i for i in devices_list])
        
        
        plt.rc('font', size=15)          # controls default text sizes
        plt.rc('xtick', labelsize=20)    # fontsize of the tick labels
        plt.rc('ytick', labelsize=20)    # fontsize of the tick labels
        # plt.rc('font', size=20)
        # plt.rc('axes', labelsize=25)
        ax = sns.heatmap(
            df_cm, 
            xticklabels=True, 
            yticklabels=True,
            annot=True,
            linewidth=.5,
            cmap="crest",
        )
        print(devices_list)
        numbered_list = list(range(1, len(devices_list) + 1))
        ax.set_xticklabels(numbered_list)
        ax.set_yticklabels(numbered_list)


        draw(f"{base_output_path}confusion.{extension}")


    if "everything" in figures or "overtime" in figures:
        run_ids_rerun = [
            "2023-10-19", 
            "2023-10-20", 
            "2023-10-21", 
            "2023-10-22", 
            "2023-10-23", 
            "2023-10-24", 
            "2023-10-25",
            "2023-10-26",
            "2023-10-27",
            "2023-10-28",
            "2023-10-29",
            "2023-10-30",
            "2023-10-31",
            "2023-11-01",
            "2023-11-02",
        ]
        reference_id = "2023-10-19"
        frames = []
        for run_id in run_ids_rerun: 
            if run_id == reference_id: 
                p = f"./data/results/{run_id}/*"
            else: 
                p = f"./data/results/{run_id}/{reference_id}/*"
            files = glob.glob(p) 
            data = pd.DataFrame(get_results(files, score, "", run_id=run_id))
            frames.append(data)

        all_data = pd.concat(frames)
        df = all_data.loc[(~all_data.mode_.str.contains("by_number")) & (~all_data.mode_.str.contains("by_time"))]
        df = all_data.loc[(all_data.mode_.str.contains("all_both"))]
        print(df)  

       
        ax = sns.boxplot(
            data=df, 
            x="run_id", 
            y="val", 
            # hue="resolver",
            color="cadetblue",
        )
        plt.grid(visible=True)

        # plt.xticks(rotation=30)
        # plt.xlabel([0, 1, 2])
        ax.set_ylim(0.5, 1)
        plt.xlabel("Days")
        plt.ylabel("Balanced accuracy")

        xtickslabels = []
        for i in range(len(run_ids_rerun)):
            xtickslabels.append(i)
        ax.set_xticklabels(xtickslabels)
        
        medians = df.groupby(['run_id'])['val'].median()
        print(medians.to_latex())
        draw(f"{base_output_path}overtime.{extension}")


    if "everything" in figures or "length_vs_iat" in figures: 
        print("-------------------")
        df = data.loc[data.mode_.str.contains("padding_no_padding_both") | data.mode_.str.contains("iat_only")]
        medians = df.groupby(['mode_'])['val'].median()
        print(medians.sort_values(ascending=False).to_latex())
    
    if "everything" in figures or "up_vs_down" in figures: 
        print("-------------------")
        # df = data.loc[data.mode_.str.contains("padding_no_padding_both") | data.mode_.str.contains("padding_no_padding_up") | data.mode_.str.contains("padding_no_padding_down")]
        # medians = df.groupby(['mode_'])['val'].median()
        # print(medians.sort_values(ascending=False).to_latex())
        df = data.loc[data.mode_.str.contains("all_both") | data.mode_.str.contains("all_up") | data.mode_.str.contains("all_down")]
        medians = df.groupby(['mode_'])['val'].median()
        print(medians.sort_values(ascending=False).to_latex())
        # ax = sns.boxplot(
        #         data=df, 
        #         x="resolver", 
        #         y="val", 
        #         hue="mode_",
        #         # hue_order=hue_order,
        #         # order=order,
        # )
        # draw("")


    if "everything" in figures or "by_time" in figures:
        print("-------------------")
        solo_run_helper(
            f"{base_output_path}time.{extension}",
            data, 
            "by_time_", 
            "Time window (in seconds)", 
            score_str
        )

    if "everything" in figures or "by_number" in figures:
        print("-------------------")
        # plt.rc('font', size=22)
        # plt.rc('axes', labelsize=35)

        solo_run_helper(
            f"{base_output_path}number.{extension}",
            data, 
            "by_number_", 
            "Number of messages", 
            score_str, 
        )

    if "everything" in figures or "by_resolver" in figures:
        print("-------------------")
        df = data.loc[data.mode_.str.contains("all_both")]
        medians = df.groupby(['resolver'])['val'].median()
        print(medians.sort_values(ascending=False).to_latex())

    if "everything" in figures or "padding" in figures:
        print("-------------------")
        # plt.rc('font', size=22)
        # plt.rc('axes', labelsize=35)

        df = data.loc[
            data.mode_.str.contains(f"padding_no_padding_{args.direction}") | 
            data.mode_.str.contains(f"padding_128_bytes_{args.direction}") | 
            data.mode_.str.contains(f"padding_random_block_{args.direction}") | 
            data.mode_.str.contains("iat_only")
        ]
        # df = df.loc[data.resolver.str.contains("Cloudflare")]
        medians = df.groupby(['resolver', 'mode_', ])['val'].median()
        print(medians.sort_values(ascending=False).to_latex())

        compare_run_helper(
            f"{base_output_path}padding-{args.direction}.{extension}", 
            df,
            resolvers_names,
            resolvers_names_pretty,
            [f"padding_no_padding_{args.direction}", f"padding_128_bytes_{args.direction}", f"padding_random_block_{args.direction}", "iat_only"],
            ["No padding (length only)", "Clostest to 128-bytes padding (length only)", "Random-Block-Length Padding (length only)", "Perfect protection (IAT only)"],
            "Resolvers", 
            score_str
        )


    if "everything" in figures or "comparecrypt" in figures: 
        df = data.loc[data.mode_.str.contains("all") | data.mode_.str.contains("padding_no_padding") | data.mode_.str.contains("padding_128_bytes") | data.mode_.str.contains("padding_random_block") | data.mode_.str.contains("iat_only")]
        compare_run_helper(
            f"{base_output_path}compare-encrypted.{extension}", 
            df,
            ["doh_8.8.4.4", "doh_1.1.1.1", "dot_8.8.8.8", "dot_1.1.1.1"],
            # ["all_up","padding_no_padding_up","all_both","padding_no_padding_both","all_down","padding_no_padding_down"],
            # ["All (up)","Length only (up)","All (both)","Length only (both)","All (down)","Length only (down)"],
            ["padding_no_padding_both","padding_no_padding_up","padding_no_padding_down", "padding_random_block_both", "padding_random_block_up", "padding_random_block_down", "padding_128_bytes_both", "padding_128_bytes_up", "padding_128_bytes_down"],
            ["padding_no_padding_both","padding_no_padding_up","padding_no_padding_down", "padding_random_block_both", "padding_random_block_up", "padding_random_block_down", "padding_128_bytes_both", "padding_128_bytes_up", "padding_128_bytes_down"],
            "Resolvers", 
            score_str
        )


