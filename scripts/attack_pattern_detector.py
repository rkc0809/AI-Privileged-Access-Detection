import pandas as pd

data = pd.read_csv("../logs/login_logs.csv")

print("\nAttack Pattern Detection\n")

# Detect brute force attacks
failed = data[data["login_status"] == "failed"]

for user in failed["user"].unique():

    attempts = failed[failed["user"] == user]

    if len(attempts) >= 3:

        print("ALERT: Brute Force Attack Detected")
        print("Target User:", user)
        print("Failed Attempts:", len(attempts))
        print("---------------------------")


# Detect credential stuffing
for ip in data["ip"].unique():

    users = data[data["ip"] == ip]["user"].unique()

    if len(users) >= 3:

        print("ALERT: Credential Stuffing Detected")
        print("Source IP:", ip)
        print("Users Targeted:", len(users))
        print("---------------------------")