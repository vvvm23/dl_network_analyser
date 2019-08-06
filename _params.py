params = {
    # Shared parameters
    'train_dir': "./data/train",
    'raw_dir': "./data/raw",
    'split_set': True,
    'vocab': 50,
    'nb_steps': 500,
    'nb_classes': 9,

    # Model parameters
    'hidden_size': 300,
    'nb_lstm': 5,
    'dropout': True,
    'dropout_rate': 0.2,

    # Training parameters
    'rate_1': 0.001,
    'rate_2': 0.001,
    'batch_1': 16,
    'batch_2': 16,
    'epoch_1': 1,
    'epoch_2': 1,
    'fields': ["Timestamp", "Source IP", "Destination IP", "Protocol", "Total Fwd Packets", "Total Backward Packets", "Label"],

    # Preprocess parameter
    'max_hour': 1.0,
    'nb_val': 100,
    'h5_mode': True
}