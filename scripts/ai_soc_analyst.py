import pandas as pd
import json

# Load configuration
with open("../config/config.json") as f:
    config = json.load(f)

trusted_country = config["trusted_country"]
malicious_ips = config["malicious_ips"]

data = pd.read_csv("../logs/login_logs.csv")

print("\nAI SOC ANALYST MODULE\n")

for index,row in data.iterrows():

    signals = []

    if row["country"] != trusted_country:
        signals.append("foreign login location")

    if row["ip"] in malicious_ips:
        signals.append("known malicious IP")

    if row["login_status"] == "failed":
        signals.append("failed login attempt")

    if row["role"] == "admin":
        signals.append("privileged account access")

    if len(signals) >= 2:

        print("AI INCIDENT ANALYSIS")
        print("--------------------")
        print("User:",row["user"])
        print("Source IP:",row["ip"])

        print("\nSignals detected:")
        for s in signals:
            print("-",s)

        print("\nAI Assessment:")

        if "failed login attempt" in signals and "privileged account access" in signals:
            print("Possible brute-force attempt against a privileged account.")

        elif "known malicious IP" in signals:
            print("Connection from a known malicious IP address.")

        else:
            print("Suspicious authentication behaviour detected.")

        print("\nRecommended Response:")
        print("- Investigate login activity")
        print("- Block suspicious IP if confirmed malicious")
        print("- Enforce MFA or password reset")

        print("\n--------------------------------\n")