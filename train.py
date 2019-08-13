from keras.preprocessing.text import text_to_word_sequence
from keras.preprocessing.text import one_hot
from keras.optimizers import Adam, SGD, Nadam
from keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau

import numpy as np
from tqdm import tqdm

import h5py
from keras.utils.io_utils import HDF5Matrix

from time import time

from model import create_model
from _params import params

from random import sample

save_name = int(time())

print("Loading Training Data from file.. ", end='')
if params['split_set']:
    if params['h5_mode']:
        a_vector_text = HDF5Matrix('{0}/train_{1}_X_attack.h5'.format(params['train_dir'], params['nb_steps']), 'train_{0}_X_attack'.format(params['nb_steps']))
        a_vector_labels = HDF5Matrix('{0}/train_{1}_Y_attack.h5'.format(params['train_dir'], params['nb_steps']), 'train_{0}_Y_attack'.format(params['nb_steps']))

        b_vector_text = HDF5Matrix('{0}/train_{1}_X_benign.h5'.format(params['train_dir'], params['nb_steps']), 'train_{0}_X_benign'.format(params['nb_steps']))
        b_vector_labels = HDF5Matrix('{0}/train_{1}_Y_benign.h5'.format(params['train_dir'], params['nb_steps']), 'train_{0}_Y_benign'.format(params['nb_steps']))

        v_vector_text = HDF5Matrix('{0}/val_{1}_X_split.h5'.format(params['train_dir'], params['nb_steps']), 'val_{0}_X_split'.format(params['nb_steps']))
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
opt_1 = Adam(lr=params['rate_1']) #opt_1 = SGD(lr=params['rate_1'])
opt_2 = Adam(lr=params['rate_2']) #opt_2 = SGD(lr=params['rate_2'])
print("Done.")

early_stop = EarlyStopping(monitor='val_acc', patience=10, mode='max')
mdl_check = ModelCheckpoint('{0}/{1}_best.h5'.format(params['model_dir'], save_name), save_best_only=True, monitor='val_acc', mode='max')
#reduce_lr = ReduceLROnPlateau(monitor='val_acc', factor=0.1, patience=10, verbose=1, mode='max')

for _ in tqdm(range(50)):
    # ATTACK DATA TRAINING #
    print("Training with Attack subset..")
    random_subset = np.random.randint(a_vector_text.shape[0], size=3500)
    model.compile(loss='categorical_crossentropy', optimizer=opt_1, metrics=['accuracy'])
    model.fit(a_vector_text[random_subset, :, :], a_vector_labels[random_subset, :], epochs=params['epoch_1'], batch_size=params['batch_1'], validation_data=(v_vector_text, v_vector_labels), shuffle=False if params['h5_mode'] else True, callbacks=[early_stop, mdl_check])

    # BENIGN DATA TRAINING #
    print("Training with Benign subset..")
    random_subset = np.random.randint(a_vector_text.shape[0], size=3500)
    model.compile(loss='categorical_crossentropy', optimizer=opt_2, metrics=['accuracy'])
    model.fit(b_vector_text[random_subset, :, :], b_vector_labels[random_subset, :], epochs=params['epoch_2'], batch_size=params['batch_2'], validation_data=(v_vector_text, v_vector_labels), shuffle=False if params['h5_mode'] else True, callbacks=[early_stop, mdl_check])

print("Training complete. Save? Y/N", end='')
x = input(": ")
if x == "Y":
    model.save("{0}/{1}_final.h5".format(params['model_dir'], save_name))