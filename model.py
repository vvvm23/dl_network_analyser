import keras
from keras.layers import Dense, Activation, Dropout, Flatten, CuDNNLSTM, Bidirectional, Embedding, TimeDistributed, LSTM, InputLayer
from keras.models import Sequential
from keras.optimizers import Adam

network_params = {
    'vocab': 39,
    'nb_steps': 501,
    'hidden_size': 100,
    'nb_lstm': 2, #Stick with two for now, implement adaptable size later
    'dropout': True,
    'dropout_rate': 0.5
}

def create_model(X_shape, Y_shape):
    model = Sequential()
    model.add(InputLayer(input_shape=(X_shape[1], X_shape[2])))
    model.add(Bidirectional(LSTM(network_params['hidden_size'], return_sequences=True)))
    if network_params['dropout']:
        model.add(Dropout(network_params['dropout_rate']))
    model.add(Bidirectional(LSTM(network_params['hidden_size'], return_sequences=True)))
    if network_params['dropout']:
        model.add(Dropout(network_params['dropout_rate']))
    model.add(TimeDistributed(Dense(64, activation='relu')))
    if network_params['dropout']:
        model.add(Dropout(network_params['dropout_rate']))
    model.add(Flatten())
    model.add(Dense(Y_shape[1], activation='sigmoid'))
    model.summary()
    return model

#if __name__ == '__main__':
    #m = create_model()
    #m.summary()