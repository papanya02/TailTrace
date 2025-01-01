import sys
import json
import joblib
import numpy as np

model = joblib.load('model.joblib')

def analyze_packet(packet_data):

    feature_vector = np.array([
        packet_data["length"],  
        len(packet_data["info"]), 
    ]).reshape(1, -1)

 
    prediction = model.predict(feature_vector)


    if prediction[0] == 1:
        return "Malicious packet detected"
    else:
        return "Benign packet"

if __name__ == "__main__":
  
    packet_data = json.loads(sys.argv[1])
    result = analyze_packet(packet_data)
    print(result)
