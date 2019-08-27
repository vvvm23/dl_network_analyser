import keras
from keras.layers import Dense, Activation, Dropout, Flatten, CuDNNLSTM, Bidirectional, Embedding, TimeDistributed, LSTM, InputLayer
from keras.models import Sequential
from keras.optimizers import Adam

from _params import params

def create_model(X_shape, Y_shape, cudnn=True):
    model = Sequential()
    model.add(InputLayer(input_shape=(X_shape[1], X_shape[2]), name="input"))

    for i in range(params['nb_lstm']):
        model.add(Bidirectional(CuDNNLSTM(params['hidden_size'], return_sequences=True), name="lstm_{0}".format(i)) if cudnn 
            else Bidirectional(LSTM(params['hidden_size'], return_sequences=True), name="lstm_{0}".format(i)))
        
        if params['dropout']:
            model.add(Dropout(params['dropout_rate'], name="dropout_LSTM_{0}".format(i)))

    # Maybe remove this dense layer, and add TimeDistributed to final softmax layer
    model.add(TimeDistributed(Dense(64, activation='relu', name="dense_1")))
    if params['dropout']:
        model.add(Dropout(params['dropout_rate'], name="dropout_1"))
    model.add(Flatten(name="flatten"))
    model.add(Dense(Y_shape[1], activation='softmax', name="dense_2"))
    model.summary()
    return model