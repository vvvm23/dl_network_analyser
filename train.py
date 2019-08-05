from keras.preprocessing.text import text_to_word_sequence
from keras.preprocessing.text import one_hot
from keras.optimizers import Adam, SGD, Nadam

import numpy as np
from tqdm import tqdm
import h5py
from time import time

from model import create_model
from _params import params

print("Loading Training Data from file.. ", end='')
a_vector_text = np.load('{0}/train_300_X_attack.npy'.format(params['train_dir']))
a_vector_labels = np.load('{0}/train_300_Y_attack.npy'.format(params['train_dir']))

b_vector_text = np.load('{0}/train_300_X_benign.npy'.format(params['train_dir']))
b_vector_labels = np.load('{0}/train_300_Y_benign.npy'.format(params['train_dir']))

v_vector_text = np.load('{0}/val_300_X_split.npy'.format(params['train_dir']))
v_vector_labels = np.load('{0}/val_300_Y_split.npy'.format(params['train_dir']))
print("Done.")

print("Creating Model.. ", end='')
model = create_model(a_vector_text.shape, a_vector_labels.shape)
print("Done.")

print("Creating Optimisers.. ", end='')
opt_1 = Nadam(lr=params['rate_1']) #opt_1 = SGD(lr=params['rate_1'])
opt_2 = Nadam(lr=params['rate_2']) #opt_2 = SGD(lr=params['rate_2'])
print("Done.")

for _ in tqdm(range(20)):
    # BENIGN DATA TRAINING #
    print("Training with Benign subset..")
    model.compile(loss='categorical_crossentropy', optimizer=opt_2, metrics=['accuracy'])
    model.fit(b_vector_text, b_vector_labels, epochs=params['epoch_1'], batch_size=params['batch_1'], validation_data=(v_vector_text, v_vector_labels))

    # ATTACK DATA TRAINING #
    print("Training with Attack subset..")
    model.compile(loss='categorical_crossentropy', optimizer=opt_1, metrics=['accuracy'])
    model.fit(a_vector_text, a_vector_labels, epochs=params['epoch_2'], batch_size=params['batch_2'], validation_data=(v_vector_text, v_vector_labels))

print("Training complete. Save? Y/N", end='')
x = input(": ")
if x == "Y":
    model.save("saved_model_{0}.h5".format(int(time())))