import pandas as pd
import requests
import time
import json

API_KEY = "a867a236c0bab2de305bde63c9120f94b344c11cdca7c9d3f3e21003ca52a501cd414737de7f1bd3"

# Load configuration
with open("../config/config.json") as f:
    config = json.load(f)

malicious_ips = config["malicious_ips"]

data = pd.read_csv("../logs/login_logs.csv")

print("\nThreat Intelligence Analysis\n")

checked_ips = set()

for index, row in data.iterrows():

    ip = row["ip"]

    # Skip private IPs
    if ip.startswith("192.168"):
        continue

    if ip in checked_ips:
        continue

    checked_ips.add(ip)

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json",
        "User-Agent": "SOC-Threat-Detector"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:

        response = requests.get(url, headers=headers, params=params, timeout=10)

        if response.status_code == 200:

            result = response.json()
            abuse_score = result["data"]["abuseConfidenceScore"]

            print("IP:", ip)
            print("Abuse Score:", abuse_score)

            if abuse_score > 50:
                print("[ALERT] Malicious IP detected via AbuseIPDB")

            print("--------------------")

        else:
            raise Exception("API returned error")

        time.sleep(2)

    except Exception:

        print("API failed for IP:", ip)

        # fallback to local threat database
        if ip in malicious_ips:

            print("[ALERT] Malicious IP detected via LOCAL threat database")
            print("IP:", ip)

        else:

            print("IP not found in local threat database")

        print("--------------------")