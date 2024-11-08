#!/usr/bin/env python3

import glob 
import json
import math
import argparse 
import numpy as np 
import pandas as pd


from scipy.stats import entropy
from numpy.linalg import norm


from pathlib import Path

import matplotlib.pyplot as plt

import seaborn as sns
sns.set_style("ticks")


plt.rc('font', size=20)
plt.rcParams["font.family"] = "serif"



def draw(name: str): 
    figure = plt.gcf()  # get current figure
    figure.set_size_inches(16, 8) # set figure's size manually to your full screen (32x18)
    if name != "":
        plt.savefig(name, bbox_inches="tight", dpi = 300)
    plt.show()


def get_results(files: list) -> dict:
    res = {
        "resolver": [],
        "feature": [],
        "val": [],
        "nb": [],
        "device": [],
    }
    for f in files: 
        s =  f.split("/")
        device_name = s[len(s)-1].split('.')[0]
        with open(f) as fp: 
            tmp = json.load(fp)
            for resolver in tmp:
                for feature in tmp[resolver]: 
                    for key, nb in tmp[resolver][feature].items(): 
                        val = int(key)
                        res["resolver"].append(resolver)
                        res["feature"].append(feature)
                        res["val"].append(val)
                        res["nb"].append(nb)
                        res["device"].append(device_name)
    return res  



def jensen_shanon_from_dataframes(df1, df2, feature="length", resolver="doh_1", positive_only=False):
    """
    what do we want?
    if 2 values: (x + y) / 2 
    if 1 value : x/2 

    Tested with (and swapped for symmetry):
    distrib_A = {
       "car": 10, 
    }
    distrib_B = {
       "car": 8, 
       "credit": 9,
    }
    all_keys = {'car': '', 'credit': ''}

    """
    distrib_A = {}
    all_keys = {}
    for index, row in df1.loc[(df1['feature'] == feature) & (df1.resolver.str.contains(resolver))].iterrows():
        # print(row['val'], row['nb'])
        if not positive_only or (positive_only and row['val'] < 0): 
            distrib_A[row['val']] = row['nb']
            all_keys[row['val']] = ''

    distrib_B = {}
    for index, row in df2.loc[(df2['feature'] == feature) & (df2.resolver.str.contains(resolver))].iterrows():
        # print(row['val'], row['nb'])

        if not positive_only or (positive_only and row['val'] < 0): 
            distrib_B[row['val']] = row['nb']
            if row['val'] not in all_keys:
                all_keys[row['val']] = ''

    mixture_distrib = {}
    res = {}
    for k in all_keys: 
        if k in distrib_A and k in distrib_B:
            mixture_distrib[k] = (distrib_A[k] + distrib_B[k]) / 2

            res[k] = (distrib_A[k] * math.log(distrib_A[k] / mixture_distrib[k]) + distrib_B[k] * math.log(distrib_B[k] / mixture_distrib[k])) / 2 
        elif k in distrib_A:
            mixture_distrib[k] = distrib_A[k] / 2 
            res[k] = (distrib_A[k] * math.log(distrib_A[k] / mixture_distrib[k])) / 2 
        elif k in distrib_B: 
            mixture_distrib[k] = distrib_B[k] / 2 
            res[k] = (distrib_B[k] * math.log(distrib_B[k] / mixture_distrib[k])) / 2 

    print("res", res)
    final_sum = 0
    for k, val in res.items():
        final_sum += val
    return final_sum


if __name__ == "__main__":
    """
    Based on a RUN_ID value, 
    - compute the mean for all the results 
    - merge the various means in a single json file 
    - display in tables / graphs
    """
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('--input_path', '-i', help='The glob input path', required=True)
    
    parser.add_argument('--compare_path', '-c', help='Another glob path to compare with the input')

    parser.add_argument('--output_path', '-of', help="Where to save the figures", default="./figures/")
    parser.add_argument('--device', '-d', help='Specific device to build the distribution for')
    parser.add_argument('--feature', '-f', help='The studied feature')
    parser.add_argument('--resolvers', '-r', help='The studied resolver(s)', default="")
    parser.add_argument('--positive_only', '-po', help='Positive only values', action=argparse.BooleanOptionalAction, default=False)

    args = parser.parse_args()

    files = glob.glob(args.input_path)
    data = pd.DataFrame(get_results(files))
    print(data)

    if args.compare_path: 
        files_compare = glob.glob(args.compare_path)
        data_compare = pd.DataFrame(get_results(files_compare))

        res = jensen_shanon_from_dataframes(
                data, 
                data_compare, 
                feature=args.feature, 
                resolver=args.resolvers, 
                positive_only=args.positive_only
        )
        if args.resolvers == "":
            resolvers = "all"
        print(f"Feature: {args.feature} | Resolver: {resolvers} | Positive only: {args.positive_only}")
        print("Jensen Shanon Divergence:", res)

    # df = data.loc[((data.device.str.contains("echodot5")) |  ((data.device.str.contains("boifun_baby")))) & (data.feature.str.contains(args.feature)) & (data.resolver.str.contains("doh_8"))]

    # df = data.loc[(data.feature.str.contains(args.feature)) & (data.resolver.str.contains("doh_1"))]
    # # df = data.loc[(data.feature.str.contains(args.feature)) & (data.resolver.str.contains("doh_8"))]

    # print(df)
    # ax = sns.scatterplot(
    #     data=df, 
    #     x="val", 
    #     y="nb", 
    #     hue="device",
    # )

    # draw("")