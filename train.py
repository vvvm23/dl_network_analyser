from keras.preprocessing.text import text_to_word_sequence
from keras.preprocessing.text import one_hot

from keras.optimizers import Adam, SGD

from pprint import pprint
import pandas as pd
import numpy as np

from tqdm import tqdm
from model import create_model

from sklearn.utils.class_weight import compute_class_weight
import h5py

from time import time

from _params import params

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

a_vector_text = np.load('{0}/train_300_X_attack.npy'.format(params['train_dir']))
a_vector_labels = np.load('{0}/train_300_Y_attack.npy'.format(params['train_dir']))

b_vector_text = np.load('{0}/train_300_X_benign.npy'.format(params['train_dir']))
b_vector_labels = np.load('{0}/train_300_Y_benign.npy'.format(params['train_dir']))

v_vector_text = np.load('{0}/val_300_X_split.npy'.format(params['train_dir']))
v_vector_labels = np.load('{0}/val_300_Y_split.npy'.format(params['train_dir']))

model = create_model(a_vector_text.shape, a_vector_labels.shape)

#opt_1 = Adam(lr=0.01, beta_1=0.9, beta_2=0.999, epsilon=None, decay=0.0, amsgrad=False)
#opt_2 = Adam(lr=0.001, beta_1=0.9, beta_2=0.999, epsilon=None, decay=0.0, amsgrad=False)

opt_1 = SGD(lr=params['rate_1'])
opt_2 = SGD(lr=params['rate_2'])

#int_labels = np.argmax(a, axis=-1)
#class_weights = compute_class_weight('balanced', np.unique(int_labels), int_labels)
#d_class_weights = dict(enumerate(class_weights))

print("Attack Input Shape:", a_vector_text.shape)
print("Attack Output Shape:", a_vector_labels.shape)
  
print("Benign Input Shape:", b_vector_text.shape)
print("Benign Output Shape:", b_vector_labels.shape)

for _ in range(20):
    # BENIGN DATA TRAINING #
    model.compile(loss='categorical_crossentropy', optimizer=opt_2, metrics=['accuracy'])
    model.fit(b_vector_text, b_vector_labels, epochs=params['epoch_1'], batch_size=params['batch_1'], validation_data=(v_vector_text, v_vector_labels))

    # ATTACK DATA TRAINING #
    model.compile(loss='categorical_crossentropy', optimizer=opt_1, metrics=['accuracy'])
    model.fit(a_vector_text, a_vector_labels, epochs=params['epoch_2'], batch_size=params['batch_2'], validation_data=(v_vector_text, v_vector_labels))


model.save("saved_model_{0}.h5".format(int(time())))