from _params import params
from keras.models import load_model, Sequential
from keras.optimizers import Adam
from keras.engine.topology import preprocess_weights_for_loading
import numpy as np
from model import create_model

def convert(model_path):
    cudnn_model = load_model(model_path)
    model = create_model(cudnn_model.get_layer(index=0).input_shape, cudnn_model.get_layer(index=-1).output_shape, False)

    cudnn_weights = cudnn_model.get_weights()
    weights = preprocess_weights_for_loading(model, cudnn_weights, '1')
    model.set_weights(weights)


    opt = Adam(lr=params['rate_1'])
    model.compile(opt, loss='categorical_crossentropy', metrics=['accuracy'])
    model.save(model_path[:-3] + '_cpu.h5')

if __name__ == '__main__':
    convert("./models/1567345397_200_best.h5")