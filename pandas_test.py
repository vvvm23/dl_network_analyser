import pandas as pd

params = {
    "file_name": "./data/Wednesday-workingHours.pcap_ISCX.csv",
    "fields": ["Flow ID", "Timestamp", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Label"]
}

data_frame = pd.read_csv(params['file_name'], skipinitialspace=True, usecols=params['fields'])
print(data_frame.loc[data_frame['Label'].str.contains("DoS")])
print(data_frame.loc[data_frame['Label'].str.contains("BENIGN")])

print(data_frame)
data_frame.drop_duplicates(keep=False,inplace=True)
print(data_frame)