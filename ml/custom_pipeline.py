import sys
import logging
# required before other imports (yes; see: https://stackoverflow.com/a/20280587)
# logging.basicConfig(
#     format='%(message)s',
#     level=logging.DEBUG,
#     stream=sys.stdout
# )

import json

from joblib import Parallel, delayed
from multiprocessing import cpu_count 

from sklearn.preprocessing import LabelEncoder
from keras.utils import to_categorical

# locals 
import utils 
from model import Model 


def convert_to_NN_format(data): 
    """
    Convert data into one-hot encoded 
    eg: "my_iot_divice" -> [0, 0, 1, 0]

    Useful when dealing with a NN, as we need to convert the string labels as vectors of 1 and 0
    so it can match its final layer output
    """
    encoder = LabelEncoder()
    encoder.fit(data)
    data = encoder.transform(data)
    data = to_categorical(data)
    return data 


class CustomPipeline(object):
    """
    A class helper because I'm tired of having to pass 42 arguments everytime I call anything
    """
    def __init__(
        self,
        classifiers, 
        X_train, 
        y_train, 
        X_test, 
        y_test, 
        scoring, 
        ordered_columns,
        selected_rows,
        modes,
        input_csv,
        labelcolumn,
        nrows,
        random_state,
        n_jobs, 
        models_dir,
        output_path,
        output_hyperparameters_json,
    ):
        self.classifiers = classifiers 
        self.X_train = X_train 
        self.y_train = y_train 
        self.X_test = X_test 
        self.y_test = y_test 
        self.scoring = scoring 
        self.ordered_columns = ordered_columns
        self.selected_rows = selected_rows
        self.modes = modes
        self.input_csv = input_csv
        self.labelcolumn = labelcolumn
        self.nrows = nrows
        self.random_state = random_state
        self.n_jobs = n_jobs 
        self.models_dir = models_dir
        self.output_path = output_path
        self.output_hyperparameters_json = output_hyperparameters_json
    
    def best_of_pipeline(self):
        """
        Test multiple ML methods, pick the best one(s), and retrain/test on unseen data
        classic.png
        """
        self.pick_best_ml_method()
        self.run_best_methods()

    def load_previous_pipeline(self, model_path):
        """
        Load a pre-trained model to test against new data 
        
        eg model_path:
        "[NN]NeuralNetwork-dns_str-complete-4.pipeline"
        "data/models/RandomForestClassifier-doh_1.1.1.1-all-42.pipeline"

        """
        logging.debug(f"[+] Loading previous model: {model_path}")
        split_on_slash = model_path.split("/")
        filename = split_on_slash[-1]
        split_on_dash = filename.split('-')
        
        clf_name = split_on_dash[0] 
        clf = self.classifiers[clf_name]['clf']
        resolver = split_on_dash[1]
        
        model_base_path = '.'.join(model_path.split('.')[:-1]) # removing the extension
        
        mode_complete = split_on_dash[2]

        if "by_" in mode_complete:
            tmp = mode_complete.split('_')
            val = tmp[-1]
            mode = '_'.join(tmp[:-1])
            selected_columns = self.ordered_columns[resolver][mode][val]
        else: 
            selected_columns = self.ordered_columns[resolver][mode_complete]
         
        self.random_state = int(split_on_dash[3].replace(".pipeline", ""))

        self.run_single_model(
            selected_columns, 
            f"{clf_name}-{resolver}-{mode_complete}-{self.random_state}", 
            clf, 
            {},
            model_base_path,
        ) 

    def pick_best_ml_method(self):
        """
        Picking the best maching learning method in a dict of multiple pipelines 

        Save in: 
        - self.hyperparameters_results (all parameters)
        - self.selected_classifiers_names (only the classifiers we'd like to use later)
        """  
        self.hyperparameters_results = {}

        nn_specifics = []
        debug_i=0
        for name, cl in self.classifiers.items():
            logging.debug(f"--------") 
            logging.debug(f"[+] {name}")
            logging.debug(f"{cl['params_grid']}")
            
            # using a temporary variable, as using a NN should not destroy original values
            tmp_y_train = self.y_train 
            tmp_y_test = self.y_test
            is_nn = "[NN]" in name
            if is_nn: 
                tmp_y_train = convert_to_NN_format(tmp_y_train)
                tmp_y_test = convert_to_NN_format(tmp_y_test)
        
            m = Model(
                name, 
                self.models_dir,
                cl['clf'], 
                is_nn,
                self.X_train, 
                self.X_test, 
                tmp_y_train, 
                tmp_y_test,
                cl['params_grid'], 
                self.scoring, 
                self.random_state, 
                self.n_jobs
            )
            self.hyperparameters_results[name] = m.hyperparameters_search()
            
            if is_nn: 
                nn_specifics.append(self.hyperparameters_results[name]['score'])

            logging.debug(f"[-] {name} hyperparameters_search ended")
            # if debug_i == 1:
            #     break 
            # break # TODO: remove the break for the actual run :)
            debug_i+=1

        logging.debug(f"[-] hyperparameters_results: {self.hyperparameters_results}")
        if self.output_hyperparameters_json: 
            with open(f"{self.output_hyperparameters_json}", 'w') as f:
                json.dump(self.hyperparameters_results, f)    

        best_score = 0 
        best_name = None 
        for cl_name in self.hyperparameters_results.keys(): 
            score = self.hyperparameters_results[cl_name]['score']
            if score > best_score: 
                best_score = score
                best_name = cl_name
        
        logging.debug(f"[-] Best: {best_name} ({best_score})")
        logging.debug(f"[-] Comparison with NN (score): {nn_specifics}")

        # By default, adding the best model
        # self.selected_classifiers_names = [best_name, "Finit"]
        self.selected_classifiers_names = [best_name]
        logging.debug(f"Selected classifiers: {self.selected_classifiers_names}")
        

    def run_single_model(
        self,
        selected_columns: list, 
        name: str,
        clf, 
        clf_params: dict, 
        model_base_path: str = "",
    ):
        """
        Retrieves data from input_csv file, train and test a given classifier (usually a whole pipeline)
        """
        if "y" not in selected_columns: 
            # by default, "y" is excluded from the selected columns, but we need it to label
            selected_columns.append("y")

        d = utils.Dataset(
            self.input_csv, 
            self.labelcolumn,
            selected_columns,
            [],
            self.selected_rows,
            self.nrows, 
            self.random_state, 
        )
        
        d.prepare_data()
        self.X_train = d.X_train
        self.X_test = d.X_test
        self.y_train = d.y_train
        self.y_test = d.y_test

        is_nn = "[NN]" in name
        if is_nn: 
            self.y_train = convert_to_NN_format(self.y_train)
            self.y_test = convert_to_NN_format(self.y_test)

            # updating the number of input_dimensions based on the latest ones
            # because the model needs to be compiled with the correct numbers 
            clf.named_steps['classification'].model__input_dimensions = d.input_dimensions
            clf.named_steps['classification'].model__nb_labels = d.nb_labels
        
        # applying (best) parameters to the classifier
        for param in clf_params:
            tmp = {}
            tmp[param] = clf_params[param]
            clf.set_params(**tmp)

        m = Model(
            name, 
            self.models_dir,
            clf, 
            is_nn,
            self.X_train, 
            self.X_test, 
            self.y_train, 
            self.y_test,
            {},  
            self.scoring,
            self.random_state, 
            self.n_jobs
        )

        if model_base_path == "": 
            m.fit()
            m.test()
            m.save_model()
        else: 
            m.model_base_path = model_base_path
            m.load_model()
            m.test()

        m.save_results(f"{self.output_path}{name}.json")

    def run_with_modes(
        self, 
        clf_name: str,
        clf,
        params: dict,
        resolver,
        model_base_path: str = "",
    ): 
        """
        Run all DNS resolvers and modes
        """
        for m in self.modes: 
            if not m.startswith("by_"): 
                self.run_single_model(
                    self.ordered_columns[resolver][m], 
                    f"{clf_name}-{resolver}-{m}-{self.random_state}", 
                    clf, 
                    params,
                    model_base_path,
                )
            else: 
                for val in self.ordered_columns[resolver][m]: 
                    self.run_single_model(
                        self.ordered_columns[resolver][m][val], 
                        f"{clf_name}-{resolver}-{m}_{val}-{self.random_state}", 
                        clf, 
                        params,
                        model_base_path,
                    ) 

    def run_best_methods(self): 
        """
        Actual runs using the best model(s)
        """
        for clf_name in self.selected_classifiers_names: 
            clf = self.classifiers[clf_name]['clf']
            params = self.hyperparameters_results[clf_name]['params']
            # parallelizing just a notch for the last by_... modes to be faster
            n_jobs = int(cpu_count()//4)
            # Parallel(n_jobs=n_jobs)(
            #     delayed(self.run_with_modes)(clf_name, clf, params, resolver)
            #     for resolver in self.ordered_columns
            # )
            for resolver in self.ordered_columns:
                if "doh" in resolver: 
                    self.run_with_modes(clf_name, clf, params, resolver)



