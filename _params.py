params = {
    # Shared parameters
    'train_dir': "./data/train",
    'raw_dir': "./data/raw",
    'split_set': True,
    'vocab': 39,
    'nb_steps': 300,
    'nb_classes': 9,

    # Model parameters
    'hidden_size': 100,
    'nb_lstm': 3,
    'dropout': True,
    'dropout_rate': 0.4,

    # Training parameters
    'rate_1': 0.0001,
    'rate_2': 0.0001,
    'batch_1': 64,
    'batch_2': 64,
    'epoch_1': 1,
    'epoch_2': 3,
    'fields': ["Timestamp", "Source IP", "Destination IP", "Protocol", "Total Fwd Packets", "Total Backward Packets", "Label"],

    # Preprocess parameter
    'max_hour': 1.0,
    'nb_val': 100
}