import pandas as pd

data = pd.read_csv("../logs/login_logs.csv")

report_file = "../reports/soc_incident_report.txt"

suspicious_logins = 0
brute_force = 0
credential_stuffing = 0
malicious_ips = set()

failed = data[data["login_status"] == "failed"]

# Brute force detection
for user in failed["user"].unique():
    attempts = failed[failed["user"] == user]
    if len(attempts) >= 3:
        brute_force += 1

# Credential stuffing detection
for ip in data["ip"].unique():
    users = data[data["ip"] == ip]["user"].unique()
    if len(users) >= 3:
        credential_stuffing += 1

# Suspicious foreign logins
for index,row in data.iterrows():
    if row["country"] != "India":
        suspicious_logins += 1

# Known malicious IPs
known_bad_ips = ["45.22.11.90","103.21.244.5"]

for ip in data["ip"].unique():
    if ip in known_bad_ips:
        malicious_ips.add(ip)

with open(report_file,"w") as f:

    f.write("SOC INCIDENT REPORT\n")
    f.write("====================\n\n")

    f.write(f"Total Suspicious Logins: {suspicious_logins}\n")
    f.write(f"Brute Force Attacks: {brute_force}\n")
    f.write(f"Credential Stuffing Attempts: {credential_stuffing}\n")
    f.write(f"Malicious IPs Detected: {len(malicious_ips)}\n\n")

    f.write("Malicious IPs\n")
    f.write("--------------\n")

    for ip in malicious_ips:
        f.write(ip + "\n")

    f.write("\nRecommended Actions\n")
    f.write("-------------------\n")
    f.write("• Investigate compromised accounts\n")
    f.write("• Block malicious IPs\n")
    f.write("• Enable MFA for privileged users\n")

print("SOC Incident Report generated successfully.")