import pandas as pd

data = pd.read_csv("../logs/login_logs.csv")

print("\nSOC INCIDENT INVESTIGATION\n")

for index, row in data.iterrows():

    hour = int(row["timestamp"].split(":")[0])

    suspicious = False
    reasons = []

    if hour < 6:
        suspicious = True
        reasons.append("Login outside normal hours")

    if row["country"] != "India":
        suspicious = True
        reasons.append("Login from foreign country")

    if row["login_status"] == "failed":
        suspicious = True
        reasons.append("Failed login attempt")

    if suspicious:

        print("INCIDENT REPORT")
        print("----------------------")
        print("User:", row["user"])
        print("Time:", row["timestamp"])
        print("IP:", row["ip"])
        print("Country:", row["country"])

        print("\nInvestigation Findings:")

        for r in reasons:
            print("-", r)

        print("\nPossible Threat: Credential Compromise")
        print("Recommended Action: Investigate user activity")
        print("-----------------------------\n")