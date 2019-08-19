import time
import os
import subprocess

os.system('cls')
print("\033[1;37;40mINFO:\t\tLoading Sentinel")

from keras.models import load_model
from keras.preprocessing.text import text_to_word_sequence
from keras.preprocessing.text import one_hot

import h5py as h5
import pandas as pd
import numpy as np
from scapy.all import *
from math import floor, log2

'''
    Plan of Action
        1) Sniff and write to pcap file
        2) Process pcap file using CICFlowMeter cmd program and save to csv
        3) Send result to preprocessing script and save as npy
        4) Predict using network. Display if attack is seen.

        Pipelining multi-threaded structure

        Thread 1 Sniffs and saves to pcap file
        Thread 2 Sends to CICFlowMeter and sends data to Thread 3
        Thread 3 Runs preprocessing script and saves to npy
        Thread 4 Handles network prediction

        Thread 0 Displays UI updates
'''

PCAP_MAX_LENGTH = 2**16 # Length of pcap file before creating a new one
CIC_MIN_START = 512 # Minimum number of packets before calculating flow data
PRE_MIN_START = 64 # Minimum number of flows before preprocessing
DEBUG = True
SILENT = False

pcap_count = 0
start_time = 0

params = {
    'pkt_count': 64
}

attack_type = {
    0:"Benign",
    1:"Portscan",
    2:"DDos",
    3:"Botnet",
    4:"Infiltration",
    5:"Web Attack",
    6:"Patator",
    7:"DoS",
    8:"Heartbleed",
}

# Print Start Banner
def banner():
    f = open("./banner.txt")
    lines = f.readlines()
    print("\033[1;34;40m ", end='')
    print(''.join(lines))
    f.close()
    pass

def print_debug(msg):
    if DEBUG and not SILENT:
        print("\033[1;32;40mDEBUG:\t\t{0}".format(msg))

def print_warn(msg):
    if not SILENT:
        print("\033[1;33;40mWARNING:\t\t{0}".format(msg))

def print_error(msg):
    # Overrides silent mode
    print("\033[1;31;40mERROR:\t\t{0}".format(msg))

def print_info(msg):
    # Overrides silent mode
    print("\033[1;37;40mINFO:\t\t{0}".format(msg))


# Update and display UI
def display_ui():
    pass

def write_pkts(pkts):
    # Maybe get rid of start time and simply overwrite old.
    # But start_time gives unique session ID.
    try:
        wrpcap('{0}_sentinel_pcap_{1}.pcap'.format(start_time, pcap_count), pkts, append=True)
    except:
        print_error("Failed to write to pcap file!")
        exit()

def preprocess():
    csv_name = "{0}_sentinel_pcap_{1}.pcap_Flow.csv".format(start_time, pcap_count)
    df = pd.read_csv("./CIC_out/{0}".format(csv_name))

    current_time = -1
    active_dyad = {}
    dyad_hours = []
    for _, row in df.iterrows():
        try:
            current_time = time.mktime(time.strptime(row.loc['Timestamp'], '%d/%m/%Y %H:%M'))
        except:
            try:
                current_time = time.mktime(time.strptime(row.loc['Timestamp'], '%d/%m/%Y %H:%M:%S'))
            except:
                current_time = time.mktime(time.strptime(row.loc['Timestamp'], '%d/%m/%Y %H:%M:%S %p'))

        c_ip_pair = -1
        # Check if IP pair already exists in an actice dyad. If it does not create new dyad
        if (row.loc['Src IP'], row.loc['Dst IP']) in active_dyad:
            #c_ip_pair = (row.loc['Source IP'], row.loc['Destination IP'])
            c_ip_pair = (row.loc['Src IP'], row.loc['Dst IP'])
            pass
        elif (row.loc['Dst IP'], row.loc['Src IP']) in active_dyad:
            #c_ip_pair = (row.loc['Destination IP'], row.loc['Source IP'])
            c_ip_pair = (row.loc['Dst IP'], row.loc['Src IP'])
            pass
        else:
            #c_ip_pair = (row.loc['Source IP'], row.loc['Destination IP'])
            c_ip_pair = (row.loc['Src IP'], row.loc['Dst IP'])
            active_dyad[c_ip_pair] = []

        active_dyad[c_ip_pair].append((current_time, int(row.loc['Protocol']),
                                        floor(log2(row.loc['Tot Fwd Pkts'])) if row.loc['Tot Fwd Pkts'] else 0,
                                        floor(log2(row.loc['Tot Bwd Pkts'])) if row.loc['Tot Bwd Pkts'] else 0,
                                        row.loc['Label']))

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

    max_length = params['nb_steps'] # Find max length
    one_hot_text = [one_hot(t, params['vocab'], filters='', split='|') for t in token_streams]
    one_hot_text = [x + [0]*(max_length-len(x)) for x in one_hot_text]

    # Vectorise inputs
    X = np.zeros((len(token_streams), params['nb_steps'], params['vocab']), dtype='float16')
    for i in tqdm(range(len(one_hot_text))):
        for j in range(len(one_hot_text[i])):
            X[i, j, one_hot_text[i][j]] = 1.0

    return X
    

def format_out(lstm_out):
    # Input size, (N, 9)
    max_lstm_out = np.argmax(lstm_out, axis=1)
    for pred in max_lstm_out:
        if pred == 0:
            print_debug("Detected BENIGN flow")
        else:
            print_info("Detected {0} flow".format(attack_type[pred]))
    

def run_sentinel():
    # Setup code
    print_info("XYZ SENTINEL START.")

    scapy.all.conf.sniff_promisc = True
    cic_pkt_count = 0

    global start_time
    global pcap_count

    start_time = time.time()
    pcap_count = 0
    pcap_pkt_count = 0

    flow_count = 0
    pre_count = 1

    model_path = "./models/1565794206_500_best.h5"
    
    try:
        model = load_model(model_path)
        pass
    except:
        print_error("Failed to load model from {0}".format(model_path))
        exit()

    # Infinite Loop
    while True:
        try:
            packets = sniff(count=params['pkt_count'])
        except:
            print_error("Failed to sniff packets")

        if not params['pkt_count'] == len(packets):
            print_warn("Mismatch in number of packets sniffed")

        cic_pkt_count += len(packets)
        pcap_pkt_count += len(packets)
        for pkt in packets:    
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            print_info("{0} {1}".format(current_time, pkt.summary()))
        
        write_pkts(packets)

        # Call CIC if min has been exceeded
        if cic_pkt_count >= CIC_MIN_START:
            print_info("Passing to CIC\n")
            pcap_name = "{0}_sentinel_pcap_{1}.pcap".format(start_time, pcap_count)

            if os.system("{0}/CICFlowMeter-4.0/bin/cfm.bat {0}/{1} {0}/CIC_out/ > nul".format(os.getcwd().replace("\\", "/"), pcap_name)):
                print_error("CICFlowMeter threw an error..")
            cic_pkt_count = 0

            flow_count = sum(1 for l in open("./CIC_out/{0}_Flow.csv".format(pcap_name)))
            print_debug("Nb. Flows: {0}".format(flow_count))

        if flow_count > PRE_MIN_START * pre_count:
            # Call preprocessing script
            # Then pass to model
            print_debug("CALLED PREPROCESS")

            # Preprocess data from CIC
            lstm_in = preprocess()

            # Predict using this data
            lstm_out = model.predict()

            # Format output and display
            format_out(lstm_out)
            pre_count += 1
        
        #DEBUG
        if not pcap_pkt_count % (params['pkt_count'] * 10):
            print_debug("pcap_pkt_count = {0}".format(pcap_pkt_count))
        #END DEBUG


        # Increment pcap counter if max exceeded
        if pcap_pkt_count >= PCAP_MAX_LENGTH:
            print_info("Max PCAP length reached. Creating new file")
            pcap_count += 1
            pcap_pkt_count = 0

            if pcap_count == 2:
                exit()

def w_sniff():
    pass

def w_cic_call():
    pass

def w_pre_call():
    pass

def w_lstm_call():
    pass


if __name__ == '__main__':
    banner()
    run_sentinel()
    pass