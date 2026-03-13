import pandas as pd

data = pd.read_csv("../logs/login_logs.csv")

print("\nSOC Alerts\n")

for index, row in data.iterrows():

    hour = int(row["timestamp"].split(":")[0])

    if row["role"] == "admin" and hour < 6:
        print("ALERT: Suspicious Admin Login")
        print("User:", row["user"])
        print("Time:", row["timestamp"])
        print("Country:", row["country"])
        print("----------------------------")

    if row["login_status"] == "failed":
        print("ALERT: Failed Login Attempt")
        print("User:", row["user"])
        print("Time:", row["timestamp"])
        print("IP:", row["ip"])
        print("----------------------------")