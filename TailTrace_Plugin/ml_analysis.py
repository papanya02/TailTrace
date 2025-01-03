import json
import sys
import pandas as pd
from sklearn.preprocessing import StandardScaler

nsl_kdd_model = joblib.load('nsl_kdd_model.pkl')
unsw_model = joblib.load('unsw_nb15_model.pkl')

packet_data = json.loads(sys.argv[1])

scaler = StandardScaler()
scaled_data = scaler.fit_transform([[
    packet_data['length'],
    len(packet_data['info']),
    len(packet_data['src']),
    len(packet_data['dst']),
]])


nsl_kdd_prediction = nsl_kdd_model.predict(scaled_data)
unsw_prediction = unsw_model.predict(scaled_data)


print(f"NSL-KDD Prediction: {nsl_kdd_prediction[0]}")
print(f"UNSW-NB15 Prediction: {unsw_prediction[0]}")
