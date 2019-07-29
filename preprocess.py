import pandas as pd
import os
from math import floor, log2
import time
from pprint import pprint
from tqdm import tqdm

def raw_to_train():
    params = {
        'raw_dir': "./data/raw",
        'train_dir': "./data/train",
        'fields': ["Timestamp", "Source IP", "Destination IP", "Protocol", "Fwd Packet Length Mean", "Label"]
    }

    frames = []
    # Iterate through all dataset files and remove duplicates
    for f in tqdm(os.listdir(params['raw_dir'])):
        print(f)
        #df = pd.read_csv("{0}/{1}".format(params['raw_dir'], f), skipinitialspace=True, usecols=params['fields'], encoding='latin1')
        df = pd.read_csv("{0}/{1}".format(params['raw_dir'], f), skipinitialspace=True, encoding='latin1')

        df.drop_duplicates(keep=False,inplace=True)
        frames.append(df)
        #print(f)
        #print(df)

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

            active_dyad[c_ip_pair].append((current_time, int(row.loc['Protocol']), floor(log2(row.loc['Fwd Packet Length Mean'])) if row.loc['Fwd Packet Length Mean'] else 0, row.loc['Label']))

            if current_time > active_dyad[c_ip_pair][0][0] + 60*60 or len(active_dyad[c_ip_pair]) > 300:
                current_attack = "BENIGN"
                attacks = []
                attack = False
                for flow in active_dyad[c_ip_pair]:
                    
                    current_attack = flow[3]
                    #if flow[3] == 'DoS GoldenEye':
                    #    print("PING")
                    #    print(attacks,"\n")
                    if flow[3] != "BENIGN" and (not (current_attack in attacks)):
                        attack = True
                        print(c_ip_pair,":",flow[3])
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
                current_attack = flow[3]
                if flow[3] != "BENIGN" and (not (current_attack in attacks)):
                    attack = True
                    print(key,":",flow[3])
                    dyad_hours.append((c_ip_pair, active_dyad[c_ip_pair], current_attack))
                    attacks.append(current_attack)

            if not attack:
                dyad_hours.append((key, active_dyad[key], current_attack))

    output = []
    for dyad in tqdm(dyad_hours):
        c_string = "{0}:{1}".format(dyad[0][0], dyad[0][1])
        for flow in dyad[1]:
            c_string += "|{0}:{1}".format(flow[1], flow[2])

        #c_string += ",{0}\n".format(dyad[1][0][-1])
        c_string += ",{0}\n".format(dyad[2])
        output.append(c_string)

    f = open("./data/train/train_300.txt", 'w+', encoding='latin1')
    f.writelines(output)
    f.close()

if __name__ == '__main__':
    raw_to_train()