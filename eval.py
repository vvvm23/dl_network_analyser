from keras.models import load_model, Sequential
from keras.optimizers import Adam
import h5py
import numpy as np

from _params import params

def evaluate(model_path, eval_path_X, eval_path_Y):
    model = load_model(model_path)

    v_vector_text = np.load('{0}/val_{1}_X_split.npy'.format(params['train_dir'], params['nb_steps']))
    v_vector_labels = np.load('{0}/val_{1}_Y_split.npy'.format(params['train_dir'], params['nb_steps']))

    x, y = model.evaluate(v_vector_text, v_vector_labels)
    print(x)
    print(y)

if __name__ == '__main__':
    evaluate('./1565640698_best.h5', '{0}/val_200_X_split.npy'.format(params['train_dir']), '{0}/val_200_Y_split.npy'.format(params['train_dir']))