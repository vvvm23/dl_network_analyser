import keras
from keras.layers import Dense, Activation, Dropout, Flatten, CuDNNLSTM, Bidirectional, Embedding, TimeDistributed
from keras.models import Sequential
from keras.optimizers import Adam

network_params = {
    'vocab': 30,
    'nb_steps': 500,
    'hidden_size': 500,
    'nb_lstm': 2, #Stick with two for now, implement adaptable size later
    'dropout': True,
    'dropout_rate': 0.5
}

def create_model():
    model = Sequential()
    
    return model