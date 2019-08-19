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

pcap_count = 0
start_time = 0

params = {
    'pkt_count': 1
}

# Print Start Banner
def banner():
    f = open("./banner.txt")
    lines = f.readlines()
    print(''.join(lines))
    f.close()
    pass

# Update and display UI
def display_ui():
    pass

def write_pkts(pkts):
    # Maybe get rid of start time and simply overwrite old.
    # But start_time gives unique session ID.
    wrpcap('{0}_sentinel_pcap_{1}.pcap'.format(start_time, pcap_count), pkts, append=True)

def preprocess():
    pass

def run_sentinel():
    # Setup code
    print("INFO:\t\t XYZ SENTINEL START.")
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW

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
    #model = load_model(model_path)

    # Infinite Loop
    while True:
        packets = sniff(count=params['pkt_count'])
        cic_pkt_count += len(packets)
        pcap_pkt_count += len(packets)
        for pkt in packets:    
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            print("INFO:\t\t{0} {1}".format(current_time, pkt.summary()))
        
        write_pkts(packets)

        # Call CIC if min has been exceeded
        if cic_pkt_count >= CIC_MIN_START:
            print("INFO:\t\tPassing to CIC\n")
            #print("DEBUG:\t\t{0}/CICFlowMeter-4.0/bin/cfm.bat {0}/sentinel_pcap.pcap {0}/CIC_out.csv".format(os.getcwd().replace("\\", "/")))
            pcap_name = "{0}_sentinel_pcap_{1}.pcap".format(start_time, pcap_count)
            os.system("{0}/CICFlowMeter-4.0/bin/cfm.bat {0}/{1} {0}/CIC_out/ > nul".format(os.getcwd().replace("\\", "/"), pcap_name))
            #subprocess.call("{0}/CICFlowMeter-4.0/bin/cfm.bat {0}/sentinel_pcap.pcap {0}/CIC_out.csv".format(os.getcwd().replace("\\", "/")), startupinfo=si)
            cic_pkt_count = 0

            flow_count = sum(1 for l in open("./CIC_out/{0}_Flow.csv".format(pcap_name)))
            print("DEBUG:\t\tNb. Flows: {0}".format(flow_count))

        if flow_count > PRE_MIN_START * pre_count:
            # Call preprocessing script
            # Then pass to model
            

            pre_count += 1

        # Increment pcap counter if max exceeded
        if pcap_pkt_count >= PCAP_MAX_LENGTH:
            print("INFO:\t\tMax PCAP length reached. Creating new file")
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