#!/usr/bin/env python3

import sys
import logging

# required before other imports (yes; see: https://stackoverflow.com/a/20280587)
logging.basicConfig(
    format='%(message)s',
    level=logging.INFO,
    stream=sys.stdout
)

import glob
import json
import argparse 

import numpy as np 
import pandas as pd
import matplotlib.pyplot as plt


import seaborn as sns
sns.set_style("ticks")
# sns.color_palette("mako", as_cmap=True)
sns.color_palette("flare", as_cmap=True)
sns.set_style("whitegrid")
plt.rc('font', size=20)
plt.rc('axes', labelsize=30)
plt.rcParams["font.family"] = "serif"



def draw(name: str): 
    figure = plt.gcf()  # get current figure
    figure.set_size_inches(16, 8) # set figure's size manually to your full screen (32x18)
    if name != "":
        plt.savefig(name, bbox_inches="tight", dpi = 300)
    plt.show()



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Draw distribution of features extracted using pcap_manipulaption/PcapDistribution.py")
    parser.add_argument('--input_path_glob', '-ig', help="Glob path where all the distributions lie (will be merged)")
    parser.add_argument('--input_path_direct', '-id', help="Use this if the merge has already been done")
    parser.add_argument('--output_csv', '-o', help="Where to save the mega distrib")
    
    parser.add_argument('--feature', '-ft', help="What feature to study")

    args = parser.parse_args()


    raw_data = {
        "resolver": [],
        "feature": [],
        "value": [],
        "occurence": []
    }

    if args.input_path_glob: 
        files = glob.glob(args.input_path_glob) 
        # Going over all the distrib files and summing up the values 
        for f in files: 
            with open(f) as f: 
                json_data = json.load(f)
                for resolver in json_data: 
                    for feature, values in json_data[resolver].items():
                        for val, occurence in values.items(): 
                            raw_data['resolver'].append(resolver)
                            raw_data['feature'].append(feature)
                            raw_data['value'].append(val)
                            raw_data['occurence'].append(occurence)

        data = pd.DataFrame(raw_data)

    elif args.input_path_direct: 
        data = pd.read_csv(args.input_path_direct)

    if args.output_csv: 
        data.to_csv(args.output_csv, encoding='utf-8')

    
    """
    Now, we want to compare the distribution of values 
    """
    # excluding IAT
    data = data.loc[(~data.resolver.str.contains("ALL_RESOLVERS"))]
    # excluding DoT
    data = data.loc[(~data.resolver.str.contains("dot"))]
    data = data.loc[(data.resolver.str.contains("Google"))]

    data = data.loc[(data.feature.str.contains(args.feature))]

    # only keeping negative values (downlinks)
    data = data[data['value'] < 0]
    dff = data.groupby(["value", "resolver"]).occurence.sum().reset_index()
    print(dff)

    print(dff.var(numeric_only=True))
    # ax = sns.histplot(dff,
    #     x="value",
    #     y="occurence",
    #     hue="resolver",
    #     binwidth=10,
    #     element="step"
    # )
    # ax.set_yscale("log")

    # draw(f"figures/2023-11-22/distribuion.pdf")
