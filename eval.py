from keras.models import load_model
from sklearn.metrics import confusion_matrix

import h5py
import numpy as np

from _params import params

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
    model = load_model(model_path)

    v_vector_text = np.load('{0}/val_{1}_X_split.npy'.format(params['train_dir'], params['nb_steps']))
    v_vector_labels = np.load('{0}/val_{1}_Y_split.npy'.format(params['train_dir'], params['nb_steps']))

    loss, accuracy = model.evaluate(v_vector_text, v_vector_labels)


    Y = model.predict(v_vector_text)
    max_Y = np.argmax(Y, axis=1)
    max_r = np.argmax(v_vector_labels, axis=1)

    for i in range(len(max_Y)):
        print("Predicted: {0}    \t\t Actual: {1}     \t\t {2}".format(attack_type[max_Y[i]], attack_type[max_r[i]], "CORRECT" if max_Y[i] == max_r[i] else "INCORRECT"))

    print("Accuracy: {0}%".format(accuracy*100))

    c_matrix = confusion_matrix(max_r, max_Y)

    print(c_matrix)

if __name__ == '__main__':
    evaluate('./models/1565948451_200_best.h5', '{0}/val_200_X_benign.npy'.format(params['train_dir']), '{0}/val_200_Y_benign.npy'.format(params['train_dir']))