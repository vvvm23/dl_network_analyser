from keras.preprocessing.text import text_to_word_sequence
from keras.preprocessing.text import one_hot
from pprint import pprint
import pandas as pd
import numpy as np

from model import create_model

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

text_data = pd.read_csv("./data/train/train.txt", header=None, encoding='latin1')
text = text_data.iloc[:, 0]

text = ['|'.join(text_to_word_sequence(x, filters='', split='|')[1:]) for x in text]

text_list = [text_to_word_sequence(x, filters='', split='|') for x in text]
text_list = [x for y in text_list for x in y]
vocab_size = len(set(text_list))
one_hot_text = [one_hot(t, round(vocab_size*1.3)) for t in text]

train_data = []
for i in range(len(one_hot_text)):
    train_data.append([one_hot_text[i], attack_type[text_data.iloc[i, 1]]]) 
train_data = [ [ [[1.0 if i == x - 1 else 0.0 for i in range(round(vocab_size*1.3))] for x in t[0]], [1.0 if x == t[1] else 0.0 for x in range(len(attack_type))]] for t in train_data]

model = create_model()