import pandas as pd
import os
from math import floor, log2
import time
from tqdm import tqdm

from random import sample

import numpy as np
from keras.preprocessing.text import text_to_word_sequence
from keras.preprocessing.text import one_hot

import h5py as h5
from _params import params

# Define attack types and label mappings
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
    frames = []
    # Iterate through all dataset files and remove duplicates
    print("Reading raw data.. ", end='')
    for f in tqdm(os.listdir(params['raw_dir'])):
        df = pd.read_csv("{0}/{1}".format(params['raw_dir'], f), skipinitialspace=True, encoding='latin1')
        df.drop_duplicates(keep=False,inplace=True)
        frames.append(df)
    print("Done.")

    print("Raw to Token Stream conversion.. ", end='')
    dyad_hours = []
    for f in tqdm(frames):
        current_time = -1
        active_dyad = {}
        for index, row in tqdm(f.iterrows()):
            # Try first format, if fails try second
            try:
                current_time = time.mktime(time.strptime(row.loc['Timestamp'], '%d/%m/%Y %H:%M'))
            except:
                try:
                    current_time = time.mktime(time.strptime(row.loc['Timestamp'], '%d/%m/%Y %H:%M:%S'))
                except:
                    current_time = time.mktime(time.strptime(row.loc['Timestamp'], '%d/%m/%Y %H:%M:%S %p'))

            c_ip_pair = -1
            # Check if IP pair already exists in an actice dyad. If it does not create new dyad
            if (row.loc['Source IP'], row.loc['Destination IP']) in active_dyad:
                c_ip_pair = (row.loc['Source IP'], row.loc['Destination IP'])
                #c_ip_pair = (row.loc['Src IP'], row.loc['Dst IP'])
                pass
            elif (row.loc['Destination IP'], row.loc['Source IP']) in active_dyad:
                c_ip_pair = (row.loc['Destination IP'], row.loc['Source IP'])
                #c_ip_pair = (row.loc['Dst IP'], row.loc['Src IP'])
                pass
            else:
                c_ip_pair = (row.loc['Source IP'], row.loc['Destination IP'])
                #c_ip_pair = (row.loc['Src IP'], row.loc['Dst IP'])
                active_dyad[c_ip_pair] = []

            # Add current data to active dyad
            active_dyad[c_ip_pair].append((current_time, int(row.loc['Protocol']),
                                        floor(log2(row.loc['Total Fwd Packets'])) if row.loc['Total Fwd Packets'] else 0,
                                        floor(log2(row.loc['Total Backward Packets'])) if row.loc['Total Backward Packets'] else 0,
                                        row.loc['Label']))
            '''active_dyad[c_ip_pair].append((current_time, int(row.loc['Protocol']),
                                        floor(log2(row.loc['Tot Fwd Pkts'])) if row.loc['Tot Fwd Pkts'] else 0,
                                        floor(log2(row.loc['Tot Bwd Pkts'])) if row.loc['Tot Bwd Pkts'] else 0,
                                        row.loc['Label']))'''

            # If current time exceeds dyad "hour" or max length reached then close dyad.
            if current_time > active_dyad[c_ip_pair][0][0] + 60*params['max_hour'] or len(active_dyad[c_ip_pair]) >= params['nb_steps']:
                current_attack = "BENIGN"
                attacks = [] # Store all attacks seen in this sequence
                attack = False
                for flow in active_dyad[c_ip_pair]:
                    current_attack = flow[4] # Get current label
                    # If it is not benign and not already processed then add to result
                    if current_attack != "BENIGN" and (not (current_attack in attacks)):
                        attack = True
                        dyad_hours.append((c_ip_pair, active_dyad[c_ip_pair], current_attack))
                        attacks.append(current_attack)

                if not attack:
                    dyad_hours.append((c_ip_pair, active_dyad[c_ip_pair], current_attack))
                active_dyad.pop(c_ip_pair, None)

        # Loop through all active dyads that are not terminated early
        for key in active_dyad:
            current_attack = "BENIGN"
            attacks = []
            attack = False

            for flow in active_dyad[key]:
                current_attack = flow[4]
                # Same process as before
                if current_attack != "BENIGN" and (not (current_attack in attacks)):
                    attack = True
                    dyad_hours.append((key, active_dyad[key], current_attack))
                    attacks.append(current_attack)

            if not attack:
                dyad_hours.append((key, active_dyad[key], current_attack))

    token_streams = []
    # For each dyad, generate token streams
    for dyad in dyad_hours:
        c_string = ""
        for flow in dyad[1]:
            c_string += "{0}:{1}:{2}|".format(flow[1], flow[2], flow[3])
        
        token_streams.append(c_string[:-1])
    print("Done..")

    print("Token Stream to Vector.. ", end='')
    # One hot encode, and extend sequences
    max_length = params['nb_steps']
    one_hot_text = [one_hot(t, params['vocab'], filters='', split='|') for t in token_streams]
    one_hot_text = [x + [0]*(max_length-len(x)) for x in one_hot_text]
    
    #np_one_hot = np.array(one_hot_text)

    # Vectorise inputs
    X = np.zeros((len(token_streams), params['nb_steps'], params['vocab']), dtype='float16')
    for i in tqdm(range(len(one_hot_text))):
        for j in range(len(one_hot_text[i])):
            X[i, j, one_hot_text[i][j]] = 1.0

    # Vectorise outputs
    Y = np.zeros((len(token_streams), params['nb_classes']))
    for i in tqdm(range(len(one_hot_text))):
        Y[i, attack_type[dyad_hours[i][2]]] = 1.0
    print("Done.")

    # Split set into training and validation. If split_set is True, further split training into attack and benign
    print("Partitioning data.. ", end='')
    if (params['split_set']):
        attack_select = []
        for y in range(Y.shape[0]):
            if Y[y, 0] != 1.0:
                attack_select.append(y)

        benign_select = [x for x in range(Y.shape[0]) if x not in attack_select]

        val_select = sample(attack_select, 20)
        val_select += sample(benign_select, 20)

        attack_select = [x for x in attack_select if x not in val_select]
        benign_select = [x for x in benign_select if x not in val_select]
        
        if params['h5_mode']:
            f = h5.File('{0}/train_{1}_X_attack.h5'.format(params['train_dir'], params['nb_steps']), 'w')
            f.create_dataset('train_{0}_X_attack'.format(params['nb_steps']), data = X[attack_select, :, :])
            f.close()

            f = h5.File('{0}/train_{1}_Y_attack.h5'.format(params['train_dir'], params['nb_steps']), 'w')
            f.create_dataset('train_{0}_Y_attack'.format(params['nb_steps']), data = Y[attack_select, :])
            f.close()

            f = h5.File('{0}/train_{1}_X_benign.h5'.format(params['train_dir'], params['nb_steps']), 'w')
            f.create_dataset('train_{0}_X_benign'.format(params['nb_steps']), data = X[benign_select, :, :])
            f.close()

            f = h5.File('{0}/train_{1}_Y_benign.h5'.format(params['train_dir'], params['nb_steps']), 'w')
            f.create_dataset('train_{0}_Y_benign'.format(params['nb_steps']), data = Y[benign_select, :])
            f.close()

            f = h5.File('{0}/val_{1}_X_split.h5'.format(params['train_dir'], params['nb_steps']), 'w')
            f.create_dataset('val_{0}_X_split'.format(params['nb_steps']), data = X[val_select, :, :])
            f.close()

            f = h5.File('{0}/val_{1}_Y_split.h5'.format(params['train_dir'], params['nb_steps']), 'w')
            f.create_dataset('val_{0}_Y_split'.format(params['nb_steps']), data = Y[val_select, :])
            f.close()
        else:
            np.save('{0}/train_{1}_X_attack.npy'.format(params['train_dir'], params['nb_steps']), X[attack_select, :, :])
            np.save('{0}/train_{1}_Y_attack.npy'.format(params['train_dir'], params['nb_steps']), Y[attack_select, :])

            np.save('{0}/train_{1}_X_benign.npy'.format(params['train_dir'], params['nb_steps']), X[benign_select, :, :])
            np.save('{0}/train_{1}_Y_benign.npy'.format(params['train_dir'], params['nb_steps']), Y[benign_select, :])

            np.save('{0}/val_{1}_X_split.npy'.format(params['train_dir'], params['nb_steps']), X[val_select, :, :])
            np.save('{0}/val_{1}_Y_split.npy'.format(params['train_dir'], params['nb_steps']), Y[val_select, :])

    else:
        train_select = list(range(Y.shape[0]))
        val_select = sample(train_select, params['nb_vals'])
        train_select = [x for x in train_select if x not in val_select]

        if params['h5_mode']:
            f = h5.File('{0}/train_{1}_X_combined1.h5'.format(params['train_dir'], params['nb_steps']), 'w')
            f.create_dataset('train_{0}_X_combined1'.format(params['nb_steps']), data = X[train_select, :])
            f.close()

            f = h5.File('{0}/train_{1}_X_combined.h5'.format(params['train_dir'], params['nb_steps']), 'w')
            f.create_dataset('train_{0}_Y_combined1'.format(params['nb_steps']), data = Y[train_select, :])
            f.close()

            f = h5.File('{0}/train_{1}_X_split1.h5'.format(params['train_dir'], params['nb_steps']), 'w')
            f.create_dataset('train_{0}_Y_split1'.format(params['nb_steps']), data = X[val_select, :])
            f.close()

            f = h5.File('{0}/train_{1}_X_split1.h5'.format(params['train_dir'], params['nb_steps']), 'w')
            f.create_dataset('train_{0}_Y_split1'.format(params['nb_steps']), data = Y[val_select, :])
            f.close()
        else:
            np.save('{0}/train_300_X_combined.npy'.format(params['train_dir']), X[train_select, :])
            np.save('{0}/train_300_Y_combined.npy'.format(params['train_dir']), Y[train_select, :])

            np.save('{0}/val_300_X_combined.npy'.format(params['train_dir']), X[val_select, :])
            np.save('{0}/val_300_Y_combined.npy'.format(params['train_dir']), Y[val_select, :])
    print("Done.")

if __name__ == '__main__':
    raw_to_train()