import pandas as pd
import os
from math import floor, log2
import time
from pprint import pprint
from tqdm import tqdm

from random import sample

import numpy as np
from keras.preprocessing.text import text_to_word_sequence
from keras.preprocessing.text import one_hot

from _params import params

attack_type = {
    "BENIGN": 0,
    "PortScan": 1,
    "DDoS": 2,
    "Bot": 3,
    "Infiltration": 4,
    "Web Attack  Brute Force": 5,
    "Web Attack  XSS": 5,
    "Web Attack  Sql Injection": 5,
    "FTP-Patator": 6,
    "SSH-Patator": 6,
    "DoS slowloris": 7,
    "DoS Slowhttptest": 7,
    "DoS Hulk": 7,
    "DoS GoldenEye": 7,
    "Heartbleed": 8
}

def raw_to_train():
    #params = {
     #   'raw_dir': "./data/raw",
     #   'train_dir': "./data/train",
     #   'fields': ["Timestamp", "Source IP", "Destination IP", "Protocol", "Total Fwd Packets", "Total Backward Packets", "Label"],
     #   'split_set': True
    #}

    frames = []
    # Iterate through all dataset files and remove duplicates
    for f in tqdm(os.listdir(params['raw_dir'])):
        df = pd.read_csv("{0}/{1}".format(params['raw_dir'], f), skipinitialspace=True, encoding='latin1')

        df.drop_duplicates(keep=False,inplace=True)
        frames.append(df)

    dyad_hours = []
    for f in tqdm(frames):
        current_time = -1
        active_dyad = {}
        for index, row in f.iterrows():
            try:
                current_time = time.mktime(time.strptime(row.loc['Timestamp'], '%d/%m/%Y %H:%M'))
            except:
                current_time = time.mktime(time.strptime(row.loc['Timestamp'], '%d/%m/%Y %H:%M:%S'))
            
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

            active_dyad[c_ip_pair].append((current_time, int(row.loc['Protocol']), floor(log2(row.loc['Total Fwd Packets'])) if row.loc['Total Fwd Packets'] else 0, floor(log2(row.loc['Total Backward Packets'])) if row.loc['Total Backward Packets'] else 0, row.loc['Label']))

            if current_time > active_dyad[c_ip_pair][0][0] + 60*params['max_hour'] or len(active_dyad[c_ip_pair]) >= params['nb_steps']:
                current_attack = "BENIGN"
                attacks = []
                attack = False
                for flow in active_dyad[c_ip_pair]:
                    
                    current_attack = flow[4]
                    if current_attack != "BENIGN" and (not (current_attack in attacks)):
                        attack = True
                        dyad_hours.append((c_ip_pair, active_dyad[c_ip_pair], current_attack))
                        attacks.append(current_attack)

                if not attack:
                    dyad_hours.append((c_ip_pair, active_dyad[c_ip_pair], current_attack))
                active_dyad.pop(c_ip_pair, None)

        for key in active_dyad:
            current_attack = "BENIGN"
            attacks = []
            attack = False

            for flow in active_dyad[key]:
                current_attack = flow[4]
                if current_attack != "BENIGN" and (not (current_attack in attacks)):
                    attack = True
                    dyad_hours.append((c_ip_pair, active_dyad[c_ip_pair], current_attack))
                    attacks.append(current_attack)

            if not attack:
                dyad_hours.append((key, active_dyad[key], current_attack))

    token_streams = []
    for dyad in dyad_hours:
        c_string = ""
        for flow in dyad[1]:
            c_string += "{0}:{1}:{2}|".format(flow[1], flow[2], flow[3])
        
        token_streams.append(c_string[:-1])

    max_length = params['nb_steps']
    one_hot_text = [one_hot(t, params['vocab'], filters='', split='|') for t in token_streams]
    one_hot_text = [x + [0]*(max_length-len(x)) for x in one_hot_text]
    
    np_one_hot = np.array(one_hot_text)

    X = np.zeros((np_one_hot.shape[0], np_one_hot.shape[1], params['vocab']))
    for i in tqdm(range(len(one_hot_text))):
        for j in range(len(one_hot_text[i])):
            X[i, j, one_hot_text[i][j]] = 1.0

    Y = np.zeros((np_one_hot.shape[0], params['nb_classes']))
    for i in tqdm(range(len(one_hot_text))):
        Y[i, attack_type[dyad_hours[i][2]]] = 1.0

    print(X.shape)
    print(Y.shape)

    if (params['split_set']):
        attack_select = []
        for y in range(Y.shape[0]):
            if Y[y, 0] != 1.0:
                attack_select.append(y)

        benign_select = [x for x in range(Y.shape[0]) if x not in attack_select]

        val_select = sample(attack_select, 50)
        val_select += sample(benign_select, 50)

        attack_select = [x for x in attack_select if x not in val_select]
        benign_select = [x for x in benign_select if x not in val_select]

        np.save('{0}/train_300_X_attack1.npy'.format(params['train_dir']), X[attack_select, :])
        np.save('{0}/train_300_Y_attack1.npy'.format(params['train_dir']), Y[attack_select, :])

        np.save('{0}/train_300_X_benign1.npy'.format(params['train_dir']), X[benign_select, :])
        np.save('{0}/train_300_Y_benign1.npy'.format(params['train_dir']), Y[benign_select, :])

        np.save('{0}/val_300_X_split1.npy'.format(params['train_dir']), X[val_select, :])
        np.save('{0}/val_300_Y_split1.npy'.format(params['train_dir']), Y[val_select, :])

    else:
        train_select = list(range(Y.shape[0]))
        val_select = sample(train_select, params['nb_vals'])
        train_select = [x for x in train_select if x not in val_select]

        np.save('{0}/train_300_X_combined1.npy'.format(params['train_dir']), X[train_select, :])
        np.save('{0}/train_300_Y_combined1.npy'.format(params['train_dir']), Y[train_select, :])

        np.save('{0}/val_300_X_combined1.npy'.format(params['train_dir']), X[val_select, :])
        np.save('{0}/val_300_Y_combined1.npy'.format(params['train_dir']), Y[val_select, :])

if __name__ == '__main__':
    raw_to_train()