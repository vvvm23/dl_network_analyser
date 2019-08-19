# A WORKING TITLE LSTM INTRUSION DETECTION SYSTEM
## Overview
Keras implementation of an LSTM Neural Network to detect malicious network traffic.

The program will sniff for network packets, then, when it has accumulated enough, attempt to predict the nature of the traffic.

## Usage
In its current state, simply clone the directory and run `python sentinel.py` from the terminal.

Run `train.py` to train the network and `eval.py` to evaluate the performance of the trained network.

So far, only tested on Windows.

## Architecture
### LSTM

### Sentinel

## References
Citations for CICFlowMeter
```
Arash Habibi Lashkari, Gerard Draper-Gil, Mohammad Saiful Islam Mamun and Ali A. Ghorbani, "Characterization of Tor Traffic Using Time Based Features", In the proceeding of the 3rd International Conference on Information System Security and Privacy, SCITEPRESS, Porto, Portugal, 2017

Gerard Drapper Gil, Arash Habibi Lashkari, Mohammad Mamun, Ali A. Ghorbani, "Characterization of Encrypted and VPN Traffic Using Time-Related Features", In Proceedings of the 2nd International Conference on Information Systems Security and Privacy(ICISSP 2016) , pages 407-414, Rome , Italy

```