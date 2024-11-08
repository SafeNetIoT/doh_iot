Up-to-date: 2023-12-11.


List a set of machine learning methods, pick the best one, train and test. The usual.

# Usage 
```sh
python3 ml/main.py --help

# Example call for 2023-11-22, all modes (everything)
python3 -m sklearnex main.py \
    -i "../data/csv/2023-11-22/all.csv" \
    -o "../data/results/2023-11-22/" \
    -oh "../data/hyperparameters/2023-11-22/everything-42.json" \
    -md "../data/models/2023-11-22/" \
    -ec "../pcap_manipulation/configs/extract-v4.0.json" \
    -rc "../pcap_manipulation/configs/resolvers.json" \
    -dc "../scripts/configs/devices-v4.0.json" \
    -r "42" \
    -m "everything"

# Example call to load 2023-10-19's model and use 2023-10-20's data 
python3 -m sklearnex main.py \
    -i "../data/csv/2023-10-20/all.csv" \
    -o "../data/results/2023-10-19/" \
    -md "../data/models/2023-11-19/" \
    -ec "../pcap_manipulation/configs/extract-v3.0.json" \
    -rc "../pcap_manipulation/configs/resolvers.json" \
    -dc "../scripts/configs/devices-v3.0.json" \
    -r "12" \
    -lm "../data/models/2023-10-19/RandomForestClassifier-doh_Quad9-all_both-12.pipeline" \
    -prid "2023-10-19" &
```

See the `get_modes()` function to check the list of all possible modes. Use `-m "everything"` to start everything, or use a subset like `-m "length_only,by_time"`.

# Using
From sklearn: 
- Classifiers
    - `RandomForestClassifier`
    - `KNeighborsClassifier`
    - `ComplementNB` 
    - `LogisticRegression`
    - `LinearSVC`
    - `SVC One-Vs-One`
    - `LinearSVC One-Vs-The-Rest`
- Hyperparameters search functions
    - `HalvingRandomSearchCV`
    - `RandomizedSearchCV` (because the other does not yet work on neural networks outputs)

From imblearn: 
- `Pipeline` ([to correctly sample only the training set](https://stackoverflow.com/questions/50245684/using-smote-with-gridsearchcv-in-scikit-learn/50245954#50245954))

From keras: 
- A simple `Sequential` model from [previous works](https://github.com/anna125/ML/blob/250e00adc8ed7e26050b0a9ab1dec7f19356c1c5/NetworkTrainer.py)

From [SciKeras](https://adriangb.com/scikeras/stable/index.html): 
- `KerasClassifier` to use it as a wrapper for keras, in order to integrate it in a Pipeline

