#!/usr/bin/env python3


import glob 
import json
import os.path 
import argparse 
import numpy as np 
import pandas as pd

from pathlib import Path

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
    figure.set_size_inches(16, 8)

    # figure.set_size_inches(16, 7) # set figure's size manually to your full screen (32x18)
    if name != "":
        plt.savefig(name, bbox_inches="tight", dpi = 300)
    plt.show()


def get_data(files): 

    res_score = {
        "model": [], 
        "score": [],
    }

    res_time = {
        "model": [], 
        "mean_fit_time": [],
        "std_fit_time": [],
        "mean_score_time": [],
        "std_score_time": [],
    }

    for file in files: 
        with open(file) as f: 
            json_data = json.load(f)
            print(json_data)
            for model,data in json_data.items(): 
                print(model, data)
                res_score['model'].append(model)
                res_score['score'].append(data['score'])

                for i in range(len(data['times']['mean_fit_time'])): 
                    for key,val in data['times'].items(): 
                        res_time[key].append(data['times'][key][i])
                        # res['std_fit_time'].append(data['times']['std_fit_time'][i])
                        # res['mean_score_time'].append(data['times']['mean_score_time'][i])
                        # res['std_score_time'].append(data['times']['std_score_time'][i])
                    res_time['model'].append(model)
    return res_score, res_time
                

if __name__ == "__main__":
    """
    - compare the  
    - display in tables / graphs
    """
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('--figures', '-f', help="Generate figures or specific list of ids (eg: '11,14,15')", default="everything")
    parser.add_argument('--input_path', '-i', help="Glob path  where all the results lie", default="./data/results/*")
    parser.add_argument('--output_path', '-o', help="Where to save the figures", default="./figures/")
    parser.add_argument('--extension', '-e', help="The figures' format (default: pdf, can use png)", default="pdf")

    args = parser.parse_args()
    figures = args.figures.split(",")
    extension = args.extension

    BASE_OUTPUT_PATH=f"{args.output_path}"
    EXTENSION=args.extension

    files = glob.glob(args.input_path) 
    raw_data_score, raw_data_time = get_data(files)
    df_score = pd.DataFrame(raw_data_score)
    df_time = pd.DataFrame(raw_data_time)
    print(df_score)
    print(df_time)

    medians_score = df_score.groupby(['model'])['score'].median().sort_values(ascending=False)
    print(medians_score.to_latex())


    medians_time = df_time.groupby(['model']).median().sort_values(by="mean_score_time", ascending=True)
    print(medians_time.to_latex())


    ml_methods_order = [
        "RandomForestClassifier",    
        "[NN]NeuralNetwork",         
        "LinearSVC",       
        "LogisticRegression",         
        "KNeighborsClassifier",      
        "LinearSVC One-Vs-The-Rest",  
        "SVC One-Vs-One",           
        "ComplementNB",          
    ]
    ml_methods = [
        "Neural Network",
    ]
    ax = sns.boxplot(data=df_time, x="model", y="mean_score_time", order=ml_methods_order, palette="colorblind")
    plt.xticks(rotation=90)

    draw(f"{BASE_OUTPUT_PATH}-compare_ml_methods.{EXTENSION}")
