from keras.preprocessing.text import text_to_word_sequence
from keras.preprocessing.text import one_hot

from keras.optimizers import Adam

from pprint import pprint
import pandas as pd
import numpy as np

from tqdm import tqdm
from model import create_model

from sklearn.utils import class_weight
import h5py
'''
    0 - No threat
    1 - Port scanning
    2 - Distributed DoS
    3 - Botnet
    4 - Internal Infiltration
    5 - Web Attack
    6 - Patator
    7 - DoS
    8 - Heartbleed
'''

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

def preprocess(path):
    text_data = pd.read_csv(path, header=None, encoding='latin1')
    text = text_data.iloc[:, 0]

    text = ['|'.join(text_to_word_sequence(x, filters='', split='|')[1:]) for x in text]
    text_list = [text_to_word_sequence(x, filters='', split='|') for x in text]


    text_list = [x for y in text_list for x in y]
    vocab_size = len(set(text_list))
    one_hot_text = [one_hot(t, 39, filters='', split='|') for t in text]

    _ = np.array(one_hot_text)

    max_length = 0
    for x in one_hot_text:
        n_len = len(x)
        max_length = n_len if n_len > max_length else max_length

    one_hot_text = [x + [0]*(max_length-len(x)) for x in one_hot_text]

    _ = np.array(one_hot_text) # EDIT THIS!!


    X = np.zeros((_.shape[0], _.shape[1], 39))
    for i in tqdm(range(len(one_hot_text))):
        for j in range(len(one_hot_text[i])):
            X[i, j, one_hot_text[i][j]] = 1.0

    Y = np.zeros((_.shape[0], 9))
    for i in tqdm(range(len(one_hot_text))):
        Y[i, attack_type[text_data.iloc[i, 1]]] = 1.0

    return X, Y


'''text_data = pd.read_csv("./data/train/train_300.txt", header=None, encoding='latin1')
text = text_data.iloc[:, 0]

text = ['|'.join(text_to_word_sequence(x, filters='', split='|')[1:]) for x in text]
text_list = [text_to_word_sequence(x, filters='', split='|') for x in text]


text_list = [x for y in text_list for x in y]
vocab_size = len(set(text_list))
one_hot_text = [one_hot(t, round(vocab_size*1.3), filters='', split='|') for t in text]

_ = np.array(one_hot_text)

max_length = 0
for x in one_hot_text:
    n_len = len(x)
    max_length = n_len if n_len > max_length else max_length

one_hot_text = [x + [0]*(max_length-len(x)) for x in one_hot_text]

_ = np.array(one_hot_text) # EDIT THIS!!


vector_text = np.zeros((_.shape[0], _.shape[1], round(vocab_size*1.3)))
for i in tqdm(range(len(one_hot_text))):
    for j in range(len(one_hot_text[i])):
        vector_text[i, j, one_hot_text[i][j]] = 1.0

print(vector_text.shape)

vector_labels = np.zeros((_.shape[0], 9))
for i in tqdm(range(len(one_hot_text))):
    vector_labels[i, attack_type[text_data.iloc[i, 1]]] = 1.0
'''
vector_text, vector_labels = preprocess("./data/train/train_300.txt")
val_X, val_Y = preprocess("./data/train/validation_300.txt")

print(vector_text.shape, vector_labels.shape)
print(val_X.shape, val_Y.shape)

model = create_model(vector_text.shape, vector_labels.shape)

opt = Adam(lr=0.001, beta_1=0.9, beta_2=0.999, epsilon=None, decay=0.0, amsgrad=False)
model.compile(loss='categorical_crossentropy', optimizer=opt, metrics=['accuracy'])

class_weights = {
    0: 1.0,
    1: 50.0,
    2: 50.0,
    3: 50.0,
    4: 50.0,
    5: 50.0,
    6: 50.0,
    7: 50.0,
    8: 50.0
}

print(class_weights)
print("Input Shape:", vector_text.shape)
print("Output Shape:", vector_labels.shape)
model.fit(vector_text, vector_labels, epochs=20, batch_size=64, class_weight=class_weights, validation_data=(val_X, val_Y))

model.save("saved_model.h5")