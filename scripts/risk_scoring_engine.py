import pandas as pd
import json

with open("../config/config.json") as f:
    config = json.load(f)

trusted_country = config["trusted_country"]
malicious_ips = config["malicious_ips"]
risk_high = config["risk_threshold_high"]
risk_medium = config["risk_threshold_medium"]

data = pd.read_csv("../logs/login_logs.csv")

print("\nSOC Risk Scoring Engine\n")

risk_events = []

for index, row in data.iterrows():

    risk_score = 0

    # foreign login
    if row["country"] != trusted_country:
        risk_score += 40

    # admin account
    if row["role"] == "admin":
        risk_score += 20

    # failed login
    if row["login_status"] == "failed":
        risk_score += 30

    # suspicious IP
    if row["ip"] in malicious_ips:
        risk_score += 40

    threat_level = "LOW"

    if risk_score >= risk_high:
        threat_level = "HIGH"
    elif risk_score >= risk_medium:
        threat_level = "MEDIUM"

    if risk_score >= risk_medium:

        print("ALERT: High Risk Login")
        print("User:", row["user"])
        print("IP:", row["ip"])
        print("Country:", row["country"])
        print("Risk Score:", risk_score)
        print("Threat Level:", threat_level)
        print("----------------------")

        risk_events.append({
            "user": row["user"],
            "ip": row["ip"],
            "risk_score": risk_score,
            "threat": threat_level
        })

print("\nTotal High Risk Events:", len(risk_events))