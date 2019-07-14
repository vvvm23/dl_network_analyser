import keras
from keras.layers import Dense, Activation, Dropout, Flatten, CuDNNLSTM, Bidirectional, Embedding, TimeDistributed
from keras.models import Sequential
from keras.optimizers import Adam

network_params = {
    'vocab': 30,
    'nb_steps': 200,
    'hidden_size': 500,
    'nb_lstm': 2, #Stick with two for now, implement adaptable size later
    'dropout': True,
    'dropout_rate': 0.5
}

def create_model():
    model = Sequential()
    model.add(Embedding(network_params['vocab'], 64, input_length = network_params['nb_steps']))
    model.add(Bidirectional(CuDNNLSTM(network_params['hidden_size'], return_sequences=True)))
    if network_params['dropout']:
        model.add(Dropout(network_params['dropout_rate']))
    model.add(Bidirectional(CuDNNLSTM(network_params['hidden_size'], return_sequences=True)))
    if network_params['dropout']:
        model.add(Dropout(network_params['dropout_rate']))
    model.add(TimeDistributed(Dense(64, activation='relu')))
    if network_params['dropout']:
        model.add(Dropout(network_params['dropout_rate']))
    model.add(TimeDistributed(Dense(1, activation='sigmoid')))
    return model

if __name__ == '__main__':
    m = create_model()
    m.summary()