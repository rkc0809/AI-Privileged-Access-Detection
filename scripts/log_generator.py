import csv
import random
from datetime import datetime, timedelta

users = ["user1", "user2", "user3", "admin1"]
countries = ["India", "India", "India", "India", "Russia", "China"]
ips = [
    "192.168.1.10",
    "192.168.1.20",
    "192.168.1.30",
    "45.22.11.90",
    "103.21.244.5"
]

rows = []

start_time = datetime.now()

for i in range(120):

    user = random.choice(users)

    role = "admin" if "admin" in user else "user"

    country = random.choice(countries)

    ip = random.choice(ips)

    login_status = random.choice(["success", "success", "success", "failed"])

    time = start_time + timedelta(minutes=i*5)

    timestamp = time.strftime("%H:%M")

    rows.append([
        timestamp,
        user,
        ip,
        country,
        login_status,
        role
    ])

with open("../logs/login_logs.csv", "w", newline="") as f:

    writer = csv.writer(f)

    writer.writerow([
        "timestamp",
        "user",
        "ip",
        "country",
        "login_status",
        "role"
    ])

    writer.writerows(rows)

print("Login logs generated successfully.")