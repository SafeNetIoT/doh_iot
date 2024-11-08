#!/usr/bin/env python3

import sys
import logging
import os.path 

from pathlib import Path


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
import matplotlib as mpl
import seaborn as sns
sns.set_style("ticks")
# sns.color_palette("mako", as_cmap=True)
sns.color_palette("flare", as_cmap=True)
# sns.set_style("whitegrid")
sns.set_style("whitegrid", {'axes.grid' : False})
plt.rc('font', size=20)
plt.rc('axes', labelsize=30)
plt.rcParams["font.family"] = "serif"

from matplotlib.patches import PathPatch



def draw(name: str): 
    figure = plt.gcf()  # get current figure
    figure.set_size_inches(16, 8) # set figure's size manually to your full screen (32x18)
    if name != "":
        plt.savefig(name, bbox_inches="tight", dpi = 300)
    plt.show()


def adjust_box_widths(g, fac):
    """
    Adjust the withs of a seaborn-generated boxplot.
    """

    # iterating through Axes instances
    for ax in g.axes:

        # iterating through axes artists:
        for c in ax.get_children():

            # searching for PathPatches
            if isinstance(c, PathPatch):
                # getting current width of box:
                p = c.get_path()
                verts = p.vertices
                verts_sub = verts[:-1]
                xmin = np.min(verts_sub[:, 0])
                xmax = np.max(verts_sub[:, 0])
                xmid = 0.5*(xmin+xmax)
                xhalf = 0.5*(xmax - xmin)

                # setting new width of box
                xmin_new = xmid-fac*xhalf
                xmax_new = xmid+fac*xhalf
                verts_sub[verts_sub[:, 0] == xmin, 0] = xmin_new
                verts_sub[verts_sub[:, 0] == xmax, 0] = xmax_new

                # setting new width of median line
                for l in ax.lines:
                    if np.all(l.get_xdata() == [xmin, xmax]):
                        l.set_xdata([xmin_new, xmax_new])
                        
                        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze features extracted using pcap_manipulaption/PcapExtractAll.py")
    parser.add_argument('--input_path_glob', '-ig', help="Glob path where all the distributions lie (will be merged in a DataFrame)")
    parser.add_argument('--output_path', '-o', help="Where to save the figures", default="./figures/")
    parser.add_argument('--extension', '-e', help="The figures' format (default: pdf, can use png)", default="pdf")

    parser.add_argument('--figures', '-f', help="Figures to draw")

    args = parser.parse_args()

    base_output_path = f"{args.output_path}/"
    Path(base_output_path).mkdir(parents=True, exist_ok=True)
    base_output_path = f"{base_output_path}raw-" 
    extension = args.extension


    frames = []
    files = glob.glob(args.input_path_glob) 
    
    # source: PcapExtractAll
    colnames=["device_name","device_class","length", "iat", "nb_queries","type","ancount","direction"]

    for f in files: 
        tmp = pd.read_csv(f, names=colnames)
        frames.append(tmp)

    df = pd.concat(frames, ignore_index=True, sort=False)
    print(df)

    if "cdf_length_dev" in args.figures: 
        sns.ecdfplot(data=df, x="length", hue="device_name")  
        draw("")
    elif "cdf_length_class" in args.figures: 
        ax = sns.ecdfplot(data=df, x="length", hue="device_class")  
        leg = ax.get_legend()
        new_title = ''
        leg.set_title(new_title)
        ax.set(xlabel='Length')
        draw(f"{base_output_path}dev_class.{extension}")
    elif "cdf_iat_dev" in args.figures: 
        sns.ecdfplot(data=df, x="iat", hue="device_name")  
        draw("")
    elif "corr" in args.figures:
        df = df.apply(lambda x: pd.factorize(x)[0])
        # print(df.describe())
        print(df.corr(method="pearson", numeric_only=False))
        # print(df.corr(method="kendall"))
    elif "bp_length_class": 
        df["length"]=(df["length"]-df["length"].min())/(df["length"].max()-df["length"].min())
        df["iat"]=(df["iat"]-df["iat"].min())/(df["iat"].max()-df["iat"].min())

        df = pd.melt(df, id_vars=['type', 'device_class'], value_vars=['iat', "length"])
        # print(df)
        df = df[df["device_class"] != "Medical"]
        
        fig = plt.figure(figsize=(16, 8))
        ax = sns.boxplot(
            x="device_class", 
            y="value", 
            data=df, 
            hue='variable', 
            hue_order=['length', np.nan], 
            showfliers=False,
            width=0.6,
            palette="colorblind",
            linewidth=1)
        ax2 = ax.twinx()

        ax2 = sns.boxplot(ax=ax2,x="device_class", y="value", data=df, hue='variable', hue_order=[np.nan, 'iat'], showfliers=False,
                        width=0.6,linewidth=1)
        
        adjust_box_widths(fig, 0.7)

        ax.legend_.remove()
        ax2.legend_.remove()

        ax.set_ylabel(f'Message length')
        ax2.set_ylabel(f'Inter-Arrival Time')
        ax.set_xlabel("Device category")

        # select the correct patches
        patches = [patch for patch in ax.patches if type(patch) == mpl.patches.PathPatch]
        # the number of patches should be evenly divisible by the number of hatches
        hatches = ['//']
        h = hatches * (len(patches) // len(hatches))
        # iterate through the patches for each subplot
        for patch, hatch in zip(patches, h):
            patch.set_hatch(hatch)
            fc = patch.get_facecolor()
            patch.set_edgecolor(fc)
            patch.set_facecolor('none')

        # Quick and dirty way of having different patterns (sorry)
        patches = [patch for patch in ax2.patches if type(patch) == mpl.patches.PathPatch]
        # the number of patches should be evenly divisible by the number of hatches
        hatches = ['..']
        h = hatches * (len(patches) // len(hatches))
        # iterate through the patches for each subplot
        for patch, hatch in zip(patches, h):
            patch.set_hatch(hatch)
            fc = patch.get_facecolor()
            patch.set_edgecolor(fc)
            patch.set_facecolor('none')

        l = ax2.legend(["Length", "IAT"])

        hatches = ['//', '..']
        for lp, hatch in zip(l.get_patches(), hatches):
            lp.set_hatch(hatch)
            fc = lp.get_facecolor()
            lp.set_edgecolor(fc)
            lp.set_facecolor('none')
        ax2.set_ylim([0, 0.03])
        ax.set_ylim([0,1])
        ax.tick_params(axis='x', rotation=45)

        draw(f"{base_output_path}bp_length_class.{extension}")


