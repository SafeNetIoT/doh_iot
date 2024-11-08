import sys
import logging

# required before other imports (yes; see: https://stackoverflow.com/a/20280587)
# logging.basicConfig(
#     format='%(message)s',
#     level=logging.INFO,
#     stream=sys.stdout
# )

import json 
import pandas as pd
from os import path

import joblib
sys.modules['sklearn.externals.joblib'] = joblib

from sklearn import metrics
from sklearn.model_selection import cross_validate

# hyperparameters tuning
from sklearn.experimental import enable_halving_search_cv  # noqa
from sklearn.model_selection import HalvingRandomSearchCV
from sklearn.model_selection import RandomizedSearchCV

# keras specifics
from keras.models import load_model

# I/O
from joblib import dump, load


class Model(object):
    """
    More or less agnostic model; wrapper for sklearn
    Used to instrument the overall training/testing/evaluating pipeline

    Design: no helper function for the pipeline. People (me) should think about what's going on, actually. 
    """
    def __init__(self, name: str, dir: str, clf, is_nn, X_train, X_test, y_train, y_test, params_grid: dict, scoring, random_state: int, n_jobs: int):
        """
        clf: classifier already instanciated
        """
        super(Model, self).__init__()
        self.name = name
        self.dir = dir

        # using two different models just to be sure which one we're using
        self.clf = clf
        self.clf_fit = None

        self.is_nn = is_nn # is the current model a mean neural network or a cool-yet-sophisiticated sklearn classifier
        
        self.X_train = X_train 
        self.X_test = X_test 
        self.y_train = y_train 
        self.y_test = y_test
        
        self.params_grid = params_grid

        self.scoring = scoring
        self.random_state = random_state

        self.n_jobs = n_jobs

        self.results = {"name": self.name}
        
        base_name = f"{self.name.replace(' ', '')}"
        self.model_base_path = path.join(self.dir, base_name)

        self.print_model_info()

    def print_model_info(self): 
        logging.info(f"\n[+] New model: {self.name}")
        logging.info(f"Training Features Shape: {self.X_train.shape}")
        logging.info(f"Training Labels Shape: {self.y_train.shape}")
        logging.info(f"Testing Features Shape: {self.X_test.shape}")
        logging.info(f"Testing Labels Shape: {self.y_test.shape}")

    def hyperparameters_search(self) -> dict: 
        """
        Search for the best hyperparameters for the current model 
        Returns the best parameters and the best score 
        """
        # HalvingRandomSearchCV bugs with multiclass classification
        # reverting to RandomSearch for neural networks
        if self.is_nn: 
            self.search = RandomizedSearchCV(
                estimator=self.clf, 
                param_distributions=self.params_grid,
                scoring=self.scoring, 
                random_state=self.random_state, 
                n_jobs=self.n_jobs,
                error_score=0,
            )
        else: 
            self.search = HalvingRandomSearchCV(
                estimator=self.clf, 
                param_distributions=self.params_grid,
                scoring=self.scoring, 
                random_state=self.random_state, 
                factor=2, # half of candidates are selected for the next iteration 
                n_jobs=self.n_jobs,
                error_score=0,
            )

        # trying to fix joblib randomly freezing/hanging for(nearly)ever
        # https://github.com/scikit-learn/scikit-learn/issues/5115
        with joblib.parallel_backend('threading'):
            self.search.fit(self.X_train, self.y_train)

        times = {
            "mean_fit_time": list(self.search.cv_results_['mean_fit_time']),
            "std_fit_time": list(self.search.cv_results_['std_fit_time']),
            "mean_score_time": list(self.search.cv_results_['mean_score_time']),
            "std_score_time": list(self.search.cv_results_['std_score_time']),  
        }
        logging.info(f"[-] Best parameters: {self.search.best_params_}")
        logging.info(f"[-] Best score: {self.search.best_score_}")

        self.y_pred = self.search.predict(self.X_test)
        print(metrics.classification_report(self.y_test, self.y_pred))
        return {
            "params": self.search.best_params_, 
            "times": times,
            "score": self.search.best_score_
        }

    def display_results(self):
        for key, val in self.results.items(): 
            logging.info(f"[{self.name}] {key}: {val}")

    def compute_results(self): 
        """
        Computing results based on the current values of self.y_test and self.y_pred
        """
        # use a local variable so it's possible to test/compute results multiple times
        y_test = self.y_test
        y_pred = self.y_pred
        if self.is_nn: 
            # initially, outputs of NN are multi-labels, which is incompatible with confusion matrices
            # converting everything from vectors so single values
            # https://stackoverflow.com/a/46954067
            y_test = pd.DataFrame(y_test).values.argmax(axis=1)
            y_pred = pd.DataFrame(y_pred).values.argmax(axis=1)
        self.results['balanced_accuracy'] = metrics.balanced_accuracy_score(y_test, y_pred)
        self.results['classification_report'] = metrics.classification_report(y_test, y_pred, output_dict=True)
        self.results['confusion_matrix'] = metrics.confusion_matrix(y_test, y_pred).tolist()

    def fit(self): 
        """
        Helper function taking the initial classifier and fitting it into self.clf_fit 
        to keep them separated
        """
        with joblib.parallel_backend('threading'):
            self.clf_fit = self.clf.fit(self.X_train, self.y_train)

    def test(self):
        """
        Performing predictions on the test dataset
        """
        logging.info(f"[{self.name}] Prediction using self.X_test...")
        self.y_pred = self.clf_fit.predict(self.X_test)
        self.compute_results()

    def save_results(self, path): 
        """
        Save the self.results object as JSON in the specific file path
        """
        logging.info(f"[{self.name}] Saving RESULTS to {path}")
        with open(path, 'w') as f: 
            json.dump(self.results, f)
            f.write('\n')

    def save_model(self):
        """
        Save the model to a file. Probably useless but who knows.
        """
        logging.info(f"[{self.name}] Saving FIT MODEL to: {self.model_base_path}.pipeline")
        
        if self.is_nn: 
            # Save the Keras model first
            # https://adriangb.com/scikeras/stable/notebooks/Basic_Usage.html#4.-Saving-and-loading-a-model
            self.clf_fit.named_steps['classification'].model_.save(f"{self.model_base_path}.keras")
        # Finally, save the pipeline:
        dump(self.clf_fit, f"{self.model_base_path}.pipeline")

    def load_model(self):
        logging.info(f"Loading model from {self.model_base_path}")
        self.clf_fit = load(f"{self.model_base_path}.pipeline")

        if self.is_nn: 
             # Then, load the Keras model:
            self.clf_fit.named_steps['classification'].model = load_model(f"{self.model_base_path}.keras")

        
