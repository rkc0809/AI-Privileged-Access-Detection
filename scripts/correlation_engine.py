import pandas as pd
import json

# Load configuration
with open("../config/config.json") as f:
    config = json.load(f)

trusted_country = config["trusted_country"]
malicious_ips = config["malicious_ips"]
risk_high = config["risk_threshold_high"]
risk_medium = config["risk_threshold_medium"]

data = pd.read_csv("../logs/login_logs.csv")

print("\nSOC CORRELATION ENGINE\n")

incidents = []

for index,row in data.iterrows():

    signals = []
    score = 0

    # foreign login
    if row["country"] != trusted_country:
        signals.append("Foreign login")
        score += 30

    # malicious IP
    if row["ip"] in malicious_ips:
        signals.append("Known malicious IP")
        score += 40

    # failed login
    if row["login_status"] == "failed":
        signals.append("Failed login attempt")
        score += 20

    # admin account
    if row["role"] == "admin":
        signals.append("Privileged account access")
        score += 20

    if score >= risk_medium:

        incidents.append({
            "user":row["user"],
            "ip":row["ip"],
            "score":score,
            "signals":signals
        })


for incident in incidents:

    severity = "MEDIUM"

    if incident["score"] >= risk_high:
        severity = "CRITICAL"
    elif incident["score"] >= risk_medium:
        severity = "HIGH"

    print("CORRELATED INCIDENT")
    print("User:",incident["user"])
    print("Source IP:",incident["ip"])
    print("Signals:",incident["signals"])
    print("Risk Score:",incident["score"])
    print("Severity:",severity)
    print("---------------------------")