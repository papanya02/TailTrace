import sys
import json


def analyze_packet(packet_data):

    if "scan" in packet_data["info"]:
        return "Port scan detected"
    elif "ddos" in packet_data["info"]:
        return "DDoS activity detected"
    elif "malicious" in packet_data["info"]:
        return "Malware detected"
    else:
        return "No intrusion detected"

if __name__ == "__main__":
  
    packet_data = json.loads(sys.argv[1])
    result = analyze_packet(packet_data)
    print(result)
