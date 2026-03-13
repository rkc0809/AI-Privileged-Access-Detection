import pandas as pd
from sklearn.ensemble import IsolationForest

# Load login logs
data = pd.read_csv("../logs/login_logs.csv")

# Convert timestamp to hour
data["hour"] = data["timestamp"].str.split(":").str[0].astype(int)

# Convert role to numeric
data["is_admin"] = data["role"].apply(lambda x: 1 if x == "admin" else 0)

# Detect foreign login
data["foreign_login"] = data["country"].apply(lambda x: 0 if x == "India" else 1)

# Features for ML model
features = data[["hour", "is_admin", "foreign_login"]]

# Train Isolation Forest model
model = IsolationForest(contamination=0.2, random_state=42)

data["anomaly"] = model.fit_predict(features)

print("\nDetection Results:\n")
print(data[["timestamp","user","country","role","anomaly"]])