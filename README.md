# FlowSniffr Intrusion Detection System
```
===================================================================================
    
                    _,)
            _..._.-;-'      ______ _                _____       _  __  __ _____  
         .-'     `(        |  ____| |              / ____|     (_)/ _|/ _|  __ \ 
        /      ;   \       | |__  | | _____      _| (___  _ __  _| |_| |_| |__) |
       ;.' ;`  ,;  ;       |  __| | |/ _ \ \ /\ / /\___ \| '_ \| |  _|  _|  _  / 
      .'' ``. (  \ ;       | |    | | (_) \ V  V / ____) | | | | | | | | | | \ \ 
     / f_ _L \ ;  )\       |_|    |_|\___/ \_/\_/ |_____/|_| |_|_|_| |_| |_|  \_\
     \/|` '|\/;; <;/
    ((; \_/  (()

===================================================================================
```
## Overview
Keras implementation of an LSTM Neural Network to detect malicious network traffic.

The program will sniff for network packets, then, when it has accumulated enough, attempt to predict the nature of the traffic.

## Usage
### Summary
In its current state, simply clone the directory and run `python sentinel.py` from the terminal.

Run `train.py` to train the network and `eval.py` to evaluate the performance of the trained network.

So far, only tested on Windows.
### Arguments
```
python sentinel.py [args]

-Flags-                        -Description-                                    -Defaults-
-h, --help                     Display help information
-H                             Display extended help information
-v, --verbosity <level>        Set verbosity level. (0-3)                       1
-i, --interface <interface>    Set interface (eg. WiFi, Ethernet)               Ethernet
-p, --packets <integer>        Set number of packets to sniff in one pass       16
-m, --model <path>             Relative path to saved keras model (.h5 file)    Best available
-d, --detailed                 Display detailed rather than summary output      Summary      
-b, --banner                   Disable banner on startup                        Enabled         
```

## Architecture
### LSTM
To be completed

### Sentinel
To be completed

## References
Citations for CICFlowMeter
```
Arash Habibi Lashkari, Gerard Draper-Gil, Mohammad Saiful Islam Mamun and Ali A. Ghorbani, "Characterization of Tor Traffic Using Time Based Features", In the proceeding of the 3rd International Conference on Information System Security and Privacy, SCITEPRESS, Porto, Portugal, 2017
Gerard Drapper Gil, Arash Habibi Lashkari, Mohammad Mamun, Ali A. Ghorbani, "Characterization of Encrypted and VPN Traffic Using Time-Related Features", In Proceedings of the 2nd International Conference on Information Systems Security and Privacy(ICISSP 2016) , pages 407-414, Rome , Italy
```