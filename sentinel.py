import time
from datetime import datetime
import os
import subprocess
import sys

# Attempt to disable annoying logging messages
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 
import tensorflow as tf
from tensorflow import logging
logging.set_verbosity(logging.ERROR)
os.system('cls')

from keras.models import load_model
from keras.preprocessing.text import text_to_word_sequence
from keras.preprocessing.text import one_hot


import h5py as h5
import pandas as pd
import numpy as np
from scapy.all import *
from math import floor, log2

from _params import params

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

PCAP_MAX_LENGTH = 2**16 # Length of pcap file before creating a new one, deprecated
PCAP_MAX_SIZE = 9*(10**8)
CIC_MIN_START = 2**8 # Minimum number of packets before calculating flow data. Set such that min nb of CIC calls are made
PRE_MIN_START = 32 # Minimum number of flows before preprocessing
VERBOSITY = 1 # 0 - DWEI | 1 - WEI | 2 - EI | 3 - I
DEBUG = False
SILENT = False
SUMMARY = True
PKT_COUNT = 1

PCAP_PATH = "./pcap"

pcap_count = 0
start_time = 0
#interface = "WiFi"
interface = "Ethernet"

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
    if VERBOSITY == 0 and not SILENT:
        print("\033[1;32;40mDEBUG:\t\t{0}".format(msg))

def print_warn(msg):
    if VERBOSITY <= 1:
        print("\033[1;33;40mWARNING:\t\t{0}".format(msg))

def print_error(msg):
    if VERBOSITY <= 2:
        print("\033[1;31;40mERROR:\t\t{0}".format(msg))

def print_info(msg):
    print("\033[1;37;40mINFO:\t\t{0}".format(msg))

def print_attack(msg):
    print("\033[1;35;40mATTACK:\t\t{0}".format(msg))

# Update and display UI
def display_ui():
    pass

def write_pkts(pkts):
    try:
        wrpcap('{0}/{1}_sentinel_pcap_{2}.pcap'.format(PCAP_PATH, start_time, pcap_count), pkts, append=True)
    except:
        print_error("Failed to write to pcap file!")
        exit()

def preprocess(csv_name):
    df = pd.read_csv("./CIC_out/{0}".format(csv_name), skipinitialspace=True, encoding='latin1')

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
            c_ip_pair = (row.loc['Src IP'], row.loc['Dst IP'])
            pass
        elif (row.loc['Dst IP'], row.loc['Src IP']) in active_dyad:
            c_ip_pair = (row.loc['Dst IP'], row.loc['Src IP'])
            pass
        else:
            c_ip_pair = (row.loc['Src IP'], row.loc['Dst IP'])
            active_dyad[c_ip_pair] = []

        active_dyad[c_ip_pair].append((current_time, int(row.loc['Protocol']),
                                        floor(log2(row.loc['Tot Fwd Pkts'])) if row.loc['Tot Fwd Pkts'] else 0,
                                        floor(log2(row.loc['Tot Bwd Pkts'])) if row.loc['Tot Bwd Pkts'] else 0))

        # If current time exceeds dyad "hour" or max length reached then close dyad.
        if current_time > active_dyad[c_ip_pair][0][0] + 60*params['max_hour'] or len(active_dyad[c_ip_pair]) >= params['nb_steps']:
            dyad_hours.append((c_ip_pair, active_dyad[c_ip_pair]))
            active_dyad.pop(c_ip_pair, None)

    # Loop through all active dyads that are not terminated early
    for key in active_dyad:
       dyad_hours.append((key, active_dyad[key]))

    token_streams = []
    # For each dyad, generate token streams
    for dyad in dyad_hours:
        c_string = ""
        for flow in dyad[1]:
            c_string += "{0}:{1}:{2}|".format(flow[1], flow[2], flow[3])
        
        token_streams.append(c_string[:-1])

    max_length = params['nb_steps']
    one_hot_text = [one_hot(t, params['vocab'], filters='', split='|') for t in token_streams]
    one_hot_text = [x + [0]*(max_length-len(x)) for x in one_hot_text]

    # Vectorise inputs
    X = np.zeros((len(token_streams), params['nb_steps'], params['vocab']), dtype='float16')
    for i in range(len(one_hot_text)):
        for j in range(len(one_hot_text[i])):
            X[i, j, one_hot_text[i][j]] = 1.0

    return X
    

def format_out(lstm_out):
    max_lstm_out = np.argmax(lstm_out, axis=1)
    format_count = {
        0:0,
        1:0,
        2:0,
        3:0,
        4:0,
        5:0,
        6:0,
        7:0,
        8:0,
    }
    dt = datetime.now()
    dt_string = "{0}:{1}:{2}".format(dt.hour, dt.minute, dt.second)
    print_attack("Summary at {0}:".format(dt_string))
    if SUMMARY:
        for pred in max_lstm_out:
            format_count[pred] += 1

        print_attack("Detected Following Flows:")
        for attack in format_count:
            if format_count[attack]:
                if not attack == 0 or VERBOSITY == 0:
                    print_attack("\t{0}x {1}".format(format_count[attack], attack_type[attack]))
    else:
        for i in range(len(max_lstm_out)):
            pred = max_lstm_out[i]
            if pred == 0:
                print_debug("Detected BENIGN flow.\t\tProbability: {0:.3f}".format(lstm_out[i, pred]))
            else:
                print_attack("Detected {0} flow.\t\tProbability: {1:.3f}".format(attack_type[pred], lstm_out[i, pred]))

def run_sentinel():
    # Setup code
    print_info("FlowSniffR Starting.")

    scapy.all.conf.sniff_promisc = True
    cic_pkt_count = 0

    global start_time
    global pcap_count

    start_time = int(time.time())
    pcap_count = 0
    pcap_pkt_count = 0

    flow_count = 0
    pre_count = 1

    model_path = "./models/1567345397_200_best_cpu.h5"
    
    try:
        model = load_model(model_path)
        pass
    except:
        print_error("Failed to load model from {0}".format(model_path))
        exit()

    # Infinite Loop
    print_info("FlowSniffR Start")
    while True:
        #print_info("Thinking..")
        try:
            packets = sniff(count=PKT_COUNT, iface=interface)
        except:
            print_error("Failed to sniff packets")

        if not PKT_COUNT == len(packets):
            print_warn("Mismatch in number of packets sniffed")

        cic_pkt_count += len(packets)
        pcap_pkt_count += len(packets)
        
        write_pkts(packets)

        # Call CIC if min has been exceeded
        if cic_pkt_count >= CIC_MIN_START:
            print_debug("Passing to CIC")
            pcap_name = "{0}_sentinel_pcap_{1}.pcap".format(start_time, pcap_count)

            if os.system("{0}/CICFlowMeter-4.0/bin/cfm.bat {0}/{2}/{1} {0}/CIC_out/ > nul".format(os.getcwd().replace("\\", "/"), pcap_name, PCAP_PATH)):
                print_error("CICFlowMeter threw an error..")
            cic_pkt_count = 0

            flow_count = sum(1 for l in open("./CIC_out/{0}_Flow.csv".format(pcap_name)))
            print_debug("Nb. Flows: {0}".format(flow_count))

        if flow_count > PRE_MIN_START * pre_count:
            # Call preprocessing script
            # Then pass to model
            print_debug("CALLED PREPROCESS")

            # Preprocess data from CIC
            lstm_in = preprocess("{0}_sentinel_pcap_{1}.pcap_Flow.csv".format(start_time, pcap_count))

            # Predict using this data
            lstm_out = model.predict(lstm_in)

            # Format output and display
            format_out(lstm_out)
            pre_count += 1

        # Increment pcap counter if max exceeded
        if os.path.getsize("{0}/{1}_sentinel_pcap_{2}.pcap".format(PCAP_PATH, start_time, pcap_count)) >= PCAP_MAX_SIZE:
            print_info("Max PCAP length reached. Creating new file")
            pcap_count += 1
            pcap_pkt_count = 0

            if pcap_count == 2:
                exit()

# TODO: Multithread the application
def w_sniff():
    pass

def w_cic_call():
    pass

def w_pre_call():
    pass

def w_lstm_call():
    pass

# TODO: Handle command line args
# Return dictionary of parameters and their values
# or just set global vars..
def handle_args():
    FLAGS = ['-h', '--help', '-H',
             '-v', '--verbosity',
             '-i', '--interface',
             '-p', '--packets',
             '-m', '--model',
             '-s', '--summary',
             '-b', '--banner']


    for arg_i in range(1, len(sys.argv)):
        arg = sys.argv(arg_i)
        if arg in FLAGS:
            if arg in ['-h', '--help']:
                # Help arg
                pass
            elif arg == '-H':
                # Extended help arg
                pass
            elif arg in ['-v', '--verbosity']:
                # Verbosity arg
                pass
            elif arg in ['-i', '--interface']:
                # Network interface arg (Which interface to listen on)
                pass
            elif arg in ['-p', '--packets']:
                # Nb packets arg (How many packets to sniff)
                pass
            elif arg in ['-m', '--model']:
                # Model arg (Which LSTM file to use)
                pass
            elif arg in ['-s', '--summary']:
                # Summary arg (display summary or detailed log)
                pass
            elif arg in ['-b', '--banner']:
                # Banner arg (display banner?)
                pass
            
        else:
            print_error("Invalid argument {0}.".format(arg))
            print_error("See help (-h, --help) for correct usage.")
            exit()
    

if __name__ == '__main__':
    # TODO: Handle Command Line inputs for:
    # Verbosity, MIN parameters, Network Choice, pkt count
    handle_args()
    banner()
    run_sentinel()