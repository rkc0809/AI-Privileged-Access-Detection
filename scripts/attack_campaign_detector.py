import pandas as pd
import json

# load configuration
with open("../config/config.json") as f:
    config = json.load(f)

malicious_ips = config["malicious_ips"]

data = pd.read_csv("../logs/login_logs.csv")

print("\nATTACK CAMPAIGN DETECTOR\n")

for ip in data["ip"].unique():

    ip_data = data[data["ip"] == ip]

    users_targeted = ip_data["user"].nunique()

    failed_attempts = len(ip_data[ip_data["login_status"] == "failed"])

    if users_targeted >= 3:

        severity = "MEDIUM"

        if ip in malicious_ips:
            severity = "CRITICAL"

        print("ATTACK CAMPAIGN DETECTED")
        print("------------------------")
        print("Source IP:", ip)
        print("Users Targeted:", users_targeted)
        print("Failed Attempts:", failed_attempts)

        if users_targeted >= 3 and failed_attempts >= 5:
            attack_type = "Credential Stuffing"
        elif failed_attempts >= 10:
            attack_type = "Brute Force"
        else:
            attack_type = "Suspicious Activity"

        print("Attack Type:", attack_type)
        print("Severity:", severity)

        print("------------------------\n")