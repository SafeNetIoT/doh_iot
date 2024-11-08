#!/usr/bin/env python3

import sys
import logging
# required before other imports (yes; see: https://stackoverflow.com/a/20280587)
# logging.basicConfig(
#     format='%(message)s',
#     level=logging.DEBUG,
#     stream=sys.stdout
# )
logging = logging.getLogger("cst_logger_for_ml")
import warnings
warnings.filterwarnings("ignore")

# removing logs from tensorflow
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 


import glob
import copy
import json 
import argparse 

import numpy as np 
import pandas as pd

from sklearn import metrics

# useful for SVC https://scikit-learn.org/stable/modules/svm.html#tips-on-practical-use
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import MinMaxScaler

# Resampler (dataset imbalance) 
from imblearn.over_sampling import RandomOverSampler 

# Custom pipeline to avoid resampling the validation set 
# https://stackoverflow.com/a/50245954
from imblearn.pipeline import Pipeline

# Classifiers 
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import ComplementNB
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.svm import SVC 

# NN specifics
from keras.models import Sequential
from keras.layers import Dense
from scikeras.wrappers import KerasClassifier

# locals 
import utils 
from custom_pipeline import CustomPipeline
from model import Model 
 

def custom_balanced_accuracy(y_true, y_pred):
    if len(y_true.shape) != 1: 
        # initially, outputs of NN are multi-labels, which is incompatible with confusion matrices
        # converting everything from vectors so single values
        # https://stackoverflow.com/a/46954067
        y_true = pd.DataFrame(y_true).values.argmax(axis=1)
        y_pred = pd.DataFrame(y_pred).values.argmax(axis=1)
    return metrics.balanced_accuracy_score(y_true, y_pred)


def create_NN_model(input_dimensions, nb_labels):
    """
    This function is copied from NetworkTrainer.create_model() and NetworkTrainer.basic_architecture()
    https://github.com/anna125/ML/blob/250e00adc8ed7e26050b0a9ab1dec7f19356c1c5/NetworkTrainer.py   
    We recreate the rest of the process via a Sklearn pipeline
    """
    model = Sequential()
    model.add(Dense(64, input_dim=input_dimensions, activation='relu'))
    model.add(Dense(64, activation='relu'))

    model.add(Dense(nb_labels, activation='softmax'))
    model.compile(optimizer='adam',
                loss='categorical_crossentropy',
                metrics=['categorical_accuracy'])

    return model


def get_modes(modes: str, resolvers_config: dict, is_dns_str: bool) -> list[str]: 
    modes = modes.split(',')
    if is_dns_str: 
        possible_modes = [
            "complete", 
            "4",
            "3"
        ]
    else: 
        possible_modes = [
            "all_both",
            "all_up",
            "all_down", 
            "iat_only", 
            "by_time", 
            "by_number"
        ]
        for padding_strat in resolvers_config["padding_strategies"]: 
            possible_modes.append(f"{padding_strat}_both")
            possible_modes.append(f"{padding_strat}_up")
            possible_modes.append(f"{padding_strat}_down")

    if "everything" in modes: 
        actual_modes = possible_modes
    else: 
        actual_modes = list(set(possible_modes).intersection(modes))
    
    if len(actual_modes) == 0: 
        logging.error(f"No mode? {modes}")
        raise ValueError 

    return actual_modes


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read a pcap file, extract relevant features and draw their distribution")
    parser.add_argument('--input_csv', '-i', help='CSV dataset used as input', required=True)
    parser.add_argument('--output_path', '-o', help='Output JSON file', required=True)
    parser.add_argument('--output_hyperparameters_json', '-oh', help='Output JSON file for timings')
    parser.add_argument('--models_dir', '-md', help='Where to save models', default="./data/models/")
    parser.add_argument('--random', '-r', default=42, help='Seed to instantiate random state (default: 42)')
    parser.add_argument('--labelcolumn', '-lc', default="y", help='The y column in the input CSV file')
    parser.add_argument('--nrows', '-n', default=None, help='Number of lines to use from the CSV')
    parser.add_argument('--extract_config', '-ec', help='Config file containing stable parameters used for extraction', required=True)
    parser.add_argument('--resolvers_config', '-rc', help='Config file containing stable parameters used for resovlers', required=True)
    parser.add_argument('--modes', '-m', help='A comma separated list of modes to run', default="everything")
    parser.add_argument('--is_dns_str', '-ds', help='If the current dataset contains one-hot encoded clear text DNS features', action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument('--n_jobs', '-nj', help='n_jobs parameter used for sklearn (https://scikit-learn.org/stable/glossary.html#term-n_jobs)', default=-2, type=int)
    parser.add_argument('--load_model_glob', '-lm', help='The glob path to one or multiple models to use on data in input_csv')
    parser.add_argument('--previous_run_id', '-prid', help='The RUN_ID of reference for the loaded model(s)', default="rerun")
    parser.add_argument('--devices_config', '-dc', help='The JSON configuration file with devices names used to train the loaded model')

    args = parser.parse_args()

    random_state = int(args.random)
    excluded_columns = []
    nrows = None
    if(args.nrows):
        nrows = int(args.nrows)
    
    scoring = metrics.make_scorer(custom_balanced_accuracy)

    # doing so is *much* faster than going for pd.read_csv(args.input_csv, index_col=0, nrows=0).columns.tolist()
    with open(args.input_csv) as f: 
        for line in f: 
            all_columns = line.split(',')[1:] # removing the 'y'
            break 
    # remove the \n on the last column name, as it's not removed by default
    all_columns[-1] = all_columns[-1].replace('\n', '')
    
    extract_config = utils.read_conf(args.extract_config)
    resolvers_config = utils.read_conf(args.resolvers_config)

    """
    If we want to rerun a previously trained model on new data, 
    we select only the rows with the devices  present when training the model, 
    so we keep trying what the model *can* guess 
    (if we test for completely unknown classes, the model *can not* predict them)
    """
    devices_config = utils.read_conf(args.devices_config)
    selected_rows = devices_config['all_devices']

    modes = get_modes(args.modes, resolvers_config, args.is_dns_str)
    logging.debug(f"[+] Running with mode(s): {modes}")

    """
    ordered_columns: 
    {
        "dns_resolver": {
            "mode": ["col_a", "col_b", ...]
        }
    }
    """
    ordered_columns = utils.prepare_columns(all_columns, extract_config, resolvers_config, is_dns_str=args.is_dns_str)
    
    # The hyper-parameters selection is done on the first resolver, using complete DNS names or all_both mode (up+down+IAT)
    if args.is_dns_str: 
        first_resolvers_columns = ordered_columns[sorted(list(ordered_columns.keys()))[0]]['complete']
    else:   
        first_resolvers_columns = ordered_columns[sorted(list(ordered_columns.keys()))[0]]['all_both']
    first_resolvers_columns.append("y")

    # X_test and y_test should only be used as held-out data 
    # naming convention: https://en.wikipedia.org/wiki/Training,_validation,_and_test_data_sets
    d = utils.Dataset(
        args.input_csv,
        args.labelcolumn,
        first_resolvers_columns,
        [], # no excluded columns
        selected_rows, 
        nrows, 
        random_state,
    )
    d.prepare_data()

    resampler= None
    resampler = RandomOverSampler(random_state=random_state) 
    logging.debug(f"--- Resampler:{resampler}")

    # "Support Vector Machine algorithms are not scale invariant, so it is highly recommended to scale your data"
    # https://scikit-learn.org/stable/modules/svm.html#tips-on-practical-use
    scaler = StandardScaler()

    # Grids based on: 
    # https://towardsdatascience.com/hyperparameter-tuning-the-random-forest-in-python-using-scikit-learn-28d2aa77dd74
    # https://machinelearningmastery.com/hyperparameters-for-classification-machine-learning-algorithms/
    classifiers = {
        "[NN]NeuralNetwork": {
            "clf": Pipeline([
                ('scaling', MinMaxScaler()),
                ('sampling', resampler),
                ('classification', KerasClassifier(model=create_NN_model, model__input_dimensions=d.input_dimensions, model__nb_labels=d.nb_labels, random_state=random_state, verbose=0))
            ]),
            "params_grid": {
                'classification__epochs':[5, 10, 15, 20],
                'classification__batch_size': [20, 25, 30],
            }
        },
        "RandomForestClassifier": {
            "clf": Pipeline([
                ('sampling', resampler),
                ('classification', RandomForestClassifier(random_state=random_state))
            ]),
            "params_grid": {
                "classification__n_estimators": [10, 50, 100, 200, 300, 400, 500, 1000], # default: 100
                "classification__max_depth": [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, None], # default: None
                "classification__min_samples_split": [2, 5, 10], # default: 2
                "classification__max_features": ["sqrt", "log2", None], # default: sqrt
                "classification__bootstrap": [True, False], # default: True
                "classification__min_samples_leaf": [1, 2, 4], # default: 1
            }
        },        
        "KNeighborsClassifier": { 
            "clf": Pipeline([
                ('sampling', resampler),
                ('classification', KNeighborsClassifier())
            ]),
            "params_grid": {
                "classification__n_neighbors": list(range(1, 21, 2)), # default: 5
                "classification__metric": ["euclidean", "manhattan", "minkowski"], # default: minkowski
                "classification__weights": ["uniform", "distance"], # default: uniform
                "classification__leaf_size": [10, 13, 16, 20, 23, 26, 30, 33, 36, 40], # default: 30
            }
        },
        "ComplementNB": { 
            "clf": Pipeline([
                ('scaling', MinMaxScaler()),
                ('sampling', resampler),
                ('classification', ComplementNB())
            ]),
            "params_grid": {
                "classification__alpha": [0, 0.5, 1.0] # default: 1.0
            }
        },
        "LogisticRegression": { 
            "clf": Pipeline([
                ('sampling', resampler),
                ('classification', LogisticRegression(multi_class="multinomial", max_iter=400, random_state=random_state))
            ]),
            "params_grid": {
                "classification__solver": ["lbfgs", "newton-cg", "sag", "saga"], # default: lbfgs
                # removing "liblinear" because conflict w/ penalty
                # removing "newton-cholesky" because it does not support multinomial backend
                "classification__C": [10, 1.0, 0.1, 0.01] # default: 1.0
            }
        },
        "LinearSVC": { 
            "clf": Pipeline([
                ('scaling', scaler),
                ('sampling', resampler),
                ('classification', LinearSVC(multi_class="crammer_singer", random_state=random_state))
            ]),
            "params_grid": {
                "classification__C": [100, 10, 1.0, 0.1, 0.01], # default: 1.0
                "classification__loss": ["hinge", "squared_hinge"] # default: squared_hinge
            }
        },
        "SVC One-Vs-One": {
            "clf": Pipeline([
                ('scaling', scaler),
                ('sampling', resampler),
                ('classification', SVC(random_state=random_state))
            ]),
            "params_grid": {
                "classification__C": [100, 10, 1.0, 0.1, 0.01], # default: 1.0
                "classification__kernel": ["poly", "rbf", "sigmoid"] # default: rbf; not using linear as it's equivalent to LinearSVC
            }
        },
        "LinearSVC One-Vs-The-Rest": { 
            "clf": Pipeline([
                ('scaling', scaler),
                ('sampling', resampler),
                ('classification', LinearSVC(multi_class="ovr", random_state=random_state))
            ]),
            "params_grid": {
                "classification__C": [100, 10, 1.0, 0.1, 0.01], # default: 1.0
                "classification__loss": ["hinge", "squared_hinge"] # default: squared_hinge
            }
        }
    }

    p = CustomPipeline(
        classifiers, 
        d.X_train, 
        d.y_train, 
        d.X_test, 
        d.y_test, 
        scoring, 
        ordered_columns,
        selected_rows,
        modes,
        args.input_csv,
        args.labelcolumn,
        nrows,
        random_state,
        args.n_jobs, 
        args.models_dir,
        args.output_path,
        args.output_hyperparameters_json
    )

    if not args.load_model_glob:
        """
        Going for a default ML pipeline, testing multiple ML methods and picking 
        the best one before training/testing on held-out data 
        """
        p.best_of_pipeline()
    else: 
        """
        Loading a previously trained model and using some *unseen* data 
        For eg: test model trained in August with data obtained in September  
        """
        ordered_columns_dns_str = utils.prepare_columns(all_columns, extract_config, resolvers_config, is_dns_str=True)
        
        if args.is_dns_str:                 
            p.ordered_columns = ordered_columns_dns_str
        else: 
            p.ordered_columns = ordered_columns
                # updating the output path 
                
        # saving the results in <RESULTS_PATH>/<PREVIOUS_RUN_ID>/<MODEL_NAME>
        p.output_path = f"{p.output_path}{args.previous_run_id}/"
        for f in glob.glob(args.load_model_glob):
            if "dns_str" in f and not args.is_dns_str:
                # just making sure a loose glob path doesn't create impossible situations  
                continue
            p.load_previous_pipeline(f)



