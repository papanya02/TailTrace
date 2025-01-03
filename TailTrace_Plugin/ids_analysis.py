import sys
import requests


api_key = 'YOUR_ABUSEIPDB_API_KEY'
ip = sys.argv[1]

url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}'

headers = {
    'Key': api_key,
    'Accept': 'application/json'
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    data = response.json()
   
    threat_level = data['data']['abuseConfidenceScore']
    print(f"Threat Level: {threat_level}")
else:
    print("Error: Could not retrieve data from AbuseIPDB.")
