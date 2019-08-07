from keras.preprocessing.text import text_to_word_sequence
from keras.preprocessing.text import one_hot
from keras.optimizers import Adam, SGD, Nadam

import numpy as np
from tqdm import tqdm

import h5py
from keras.utils.io_utils import HDF5Matrix

from time import time

from model import create_model
from _params import params

print("Loading Training Data from file.. ", end='')
if params['split_set']:
    if params['h5_mode']:
        a_vector_text = HDF5Matrix('{0}/train_{1}_X_attack.h5'.format(params['train_dir'], params['nb_steps']), 'train_{0}_X_attack'.format(params['nb_steps']))
        a_vector_labels = HDF5Matrix('{0}/train_{1}_Y_attack.h5'.format(params['train_dir'], params['nb_steps']), 'train_{0}_Y_attack'.format(params['nb_steps']))

        b_vector_text = HDF5Matrix('{0}/train_{1}_X_benign.h5'.format(params['train_dir'], params['nb_steps']), 'train_{0}_X_benign'.format(params['nb_steps']))
        b_vector_labels = HDF5Matrix('{0}/train_{1}_Y_benign.h5'.format(params['train_dir'], params['nb_steps']), 'train_{0}_Y_benign'.format(params['nb_steps']))

        v_vector_text = HDF5Matrix('{0}/val_{1}_X_split.h5'.format(params['train_dir'], params['nb_steps']), 'val_{0}_X_split'.format(params['nb_steps'])) # CHANGE THIS
        v_vector_labels = HDF5Matrix('{0}/val_{1}_Y_split.h5'.format(params['train_dir'], params['nb_steps']), 'val_{0}_Y_split'.format(params['nb_steps']))
    else:
        a_vector_text = np.load('{0}/train_{1}_X_attack.npy'.format(params['train_dir'], params['nb_steps']))
        a_vector_labels = np.load('{0}/train_{1}_Y_attack.npy'.format(params['train_dir'], params['nb_steps']))

        b_vector_text = np.load('{0}/train_{1}_X_benign.npy'.format(params['train_dir'], params['nb_steps']))
        b_vector_labels = np.load('{0}/train_{1}_Y_benign.npy'.format(params['train_dir'], params['nb_steps']))

        v_vector_text = np.load('{0}/val_{1}_X_split.npy'.format(params['train_dir'], params['nb_steps']))
        v_vector_labels = np.load('{0}/val_{1}_Y_split.npy'.format(params['train_dir'], params['nb_steps']))
else:
    pass
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