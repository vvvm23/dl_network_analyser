import pandas as pd
import os
from math import floor, log2

'''
    1) Get raw data files
    2) Remove duplicate entries
    3) Remove irrelevant fields

'''

params = {
    'raw_dir': "./data/raw",
    'train_dir': "./data/train",
    'fields': ["Timestamp", "Source IP", "Destination IP", "Protocol", "Fwd Packet Length Mean", "Label"]
}

frames = []
# Iterate through all dataset files and remove duplicates
for f in os.listdir(params['raw_dir']):
    df = pd.read_csv("{0}/{1}".format(params['raw_dir'], f), skipinitialspace=True, usecols=params['fields'], encoding='latin1')
    df.drop_duplicates(keep=False,inplace=True)
    frames.append(df)
    #print(f)
    #print(df)

for f in frames:
    current_time = -1
    active_dyad = {}
    for index, row in f.iterrows():
        c_ip_pair = -1
        
        if (row.loc['Source IP'], row.loc['Destination IP']) in active_dyad:
            c_ip_pair = (row.loc['Source IP'], row.loc['Destination IP'])
            pass
        elif (row.loc['Destination IP'], row.loc['Source IP']) in active_dyad:
            c_ip_pair = (row.loc['Destination IP'], row.loc['Source IP'])
            pass
        else:
            c_ip_pair = (row.loc['Source IP'], row.loc['Destination IP'])
            active_dyad[c_ip_pair] = []

        active_dyad[c_ip_pair].append((row.loc['Protocol'], floor(log2(row.loc['Fwd Packet Length Mean'])) if row.loc['Fwd Packet Length Mean'] else 0.0))

    print(active_dyad)

combined_df = pd.concat(frames)
print(combined_df)