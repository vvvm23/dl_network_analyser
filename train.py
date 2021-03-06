from keras.preprocessing.text import text_to_word_sequence
from keras.preprocessing.text import one_hot
from keras.optimizers import Adam, SGD, Nadam
from keras.models import load_model
from keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau

import numpy as np
from tqdm import tqdm

import h5py
from keras.utils.io_utils import HDF5Matrix

from time import time
import sys

from model import create_model
from _params import params
import cudnn_to_cpu

from random import sample

from sklearn.utils import class_weight

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
print(a_vector_text.shape)
print(a_vector_labels.shape)
model = create_model(a_vector_text.shape, a_vector_labels.shape)
print("Done.")

print("Creating Optimisers.. ", end='')
opt_1 = Adam(lr=params['rate_1'])
print("Done.")

print("Compiling Model.. ", end='')
model.compile(loss='categorical_crossentropy', optimizer=opt_1, metrics=['accuracy'])
print("Done.")

early_stop = EarlyStopping(monitor='val_acc', patience=10, mode='max')
mdl_check = ModelCheckpoint('{0}/{1}_{2}_best.h5'.format(params['model_dir'], save_name, params['nb_steps']), 
                            save_best_only=True, monitor='val_acc', mode='max')

if len(sys.argv) == 2:
    model = load_model(sys.argv[1])

attack_length = a_vector_text.shape[0]
for _ in tqdm(range(50)):
    random_subset = np.random.randint(b_vector_text.shape[0], size=int(attack_length))

    concat_X = np.concatenate((a_vector_text, b_vector_text[random_subset, :, :]), axis=0)
    concat_Y = np.concatenate((a_vector_labels, b_vector_labels[random_subset, :]), axis=0)

    model.fit(concat_X, concat_Y,
            epochs=params['epoch_1'], batch_size=params['batch_1'],
            validation_data=(v_vector_text, v_vector_labels), 
            shuffle=False if params['h5_mode'] else True,
            callbacks=[early_stop, mdl_check])
    
print("Training complete. Save? Y/N", end='')
x = input(": ")
if x == "Y":
    model.save("{0}/{1}_{2}_final.h5".format(params['model_dir'], save_name, params['nb_steps']))

    x = input("Save CPU version? Y/N: ")
    if x == "Y":
        cudnn_to_cpu.convert("{0}/{1}_{2}_final.h5".format(params['model_dir'], save_name, params['nb_steps']))
