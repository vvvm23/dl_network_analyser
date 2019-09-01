from keras.models import load_model, Sequential
from keras.optimizers import Adam
from keras.engine.topology import preprocess_weights_for_loading

from sklearn.metrics import confusion_matrix

import h5py
import numpy as np

from _params import params
from model import create_model

attack_type = {
    0:"Benign",
    1:"Portscan",
    2:"DDos",
    3:"Botnet",
    4:"Infiltration",
    5:"Web Attack",
    6:"Patator",
    7:"DoS",
    8:"Heartbleed",
}

def evaluate(model_path, eval_path_X, eval_path_Y):

    v_vector_text = np.load('{0}/val_{1}_X_split.npy'.format(params['train_dir'], params['nb_steps']))
    v_vector_labels = np.load('{0}/val_{1}_Y_split.npy'.format(params['train_dir'], params['nb_steps']))
    
    model = load_model(model_path)
    opt = Adam(lr=params['rate_1'])
    model.compile(opt, loss='categorical_crossentropy', metrics=['accuracy'])
    loss, accuracy = model.evaluate(v_vector_text, v_vector_labels)

    Y = model.predict(v_vector_text)
    max_Y = np.argmax(Y, axis=1)
    max_r = np.argmax(v_vector_labels, axis=1)

    for i in range(len(max_Y)):
        print("Predicted: {0}    \t\t Actual: {1}     \t\t {2}".format(attack_type[max_Y[i]], attack_type[max_r[i]], "CORRECT" if max_Y[i] == max_r[i] else "INCORRECT"))

    print("Accuracy: {0}%".format(accuracy*100))
    print("Loss: {0}".format(loss))

    c_matrix = confusion_matrix(max_r, max_Y)

    print(c_matrix)

if __name__ == '__main__':
    evaluate('./models/1567001597_200_best_cpu.h5', '{0}/val_200_X_split.npy'.format(params['train_dir']), '{0}/val_200_Y_split.npy'.format(params['train_dir']))