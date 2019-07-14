import pandas as pd
import os

'''
    1) Get raw data files
    2) Remove duplicate entries
    3) Remove irrelevant fields

'''

params = {
    'raw_dir': "./data/raw",
    'train_dir': "./data/train",
    'fields': ["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Label"]
}

frames = []
for f in os.listdir(params['raw_dir']):
    df = pd.read_csv("{0}/{1}".format(params['raw_dir'], f), skipinitialspace=True, usecols=params['fields'], encoding='latin1')
    df.drop_duplicates(keep=False,inplace=True)
    frames.append(df)
    print(f)
    print(df)

combined_df = pd.concat(frames)
print(combined_df)