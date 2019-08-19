import time
import os
import subprocess

os.system('cls')
print("INFO:\t\tLoading Sentinel")
from keras.models import load_model
from keras.preprocessing.text import text_to_word_sequence
from keras.preprocessing.text import one_hot

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

PCAP_MAX_LENGTH = 16384 # Length of pcap file before creating a new one
CIC_MIN_START = 512 # Minimum number of packets before calculating flow data
PRE_MIN_START = 64 # Minimum number of flows before preprocessing
DEBUG = True
SILENT = False

pcap_count = 0
start_time = 0

params = {
    'pkt_count': 1
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
        print("\033[1;32;40m DEBUG:\t\t{0}".format(msg))

def print_warn(msg):
    if not SILENT:
        print("\033[1;33;40m WARNING:\t\t{0}".format(msg))

def print_error(msg):
    # Overrides silent mode
    print("\033[1;31;40m ERROR:\t\t{0}".format(msg))

def print_info(msg):
    # Overrides silent mode
    print("\033[1;37;40m INFO:\t\t{0}".format(msg))


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
    pass

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

    model_path = ""
    
    try:
        #model = load_model(model_path)
        pass
    except:
        print_error("Failed to load model from {0}".format(model_path))

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

            pre_count += 1
            #exit()

        # Increment pcap counter if max exceeded
        
        # DEBUG
        if not pcap_pkt_count % 10:
            print_debug("pcap_pkt_count = {0}".format(pcap_pkt_count))

        if pcap_pkt_count >= PCAP_MAX_LENGTH:
            print_info("Max PCAP length reached. Creating new file")
            pcap_count += 1
            pcap_pkt_count = 0

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