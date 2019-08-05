import keras
from keras.layers import Dense, Activation, Dropout, Flatten, CuDNNLSTM, Bidirectional, Embedding, TimeDistributed, LSTM, InputLayer
from keras.models import Sequential
from keras.optimizers import Adam

from _params import params

#network_params = {
#    'vocab': 39,
#    'nb_steps': 300,
#    'hidden_size': 100,
#    'nb_lstm': 3, 
#    'dropout': True,
#    'dropout_rate': 0.4
#}

def create_model(X_shape, Y_shape):
    model = Sequential()
    model.add(InputLayer(input_shape=(X_shape[1], X_shape[2])))

    for _ in range(params['nb_lstm']):
        model.add(Bidirectional(CuDNNLSTM(params['hidden_size'], return_sequences=True)))
        if params['dropout']:
            model.add(Dropout(params['dropout_rate']))

    model.add(TimeDistributed(Dense(64, activation='relu')))
    if params['dropout']:
        model.add(Dropout(params['dropout_rate']))
    model.add(Flatten())
    model.add(Dense(Y_shape[1], activation='softmax'))
    model.summary()
    return model