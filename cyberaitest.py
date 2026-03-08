"""
CybAI Mini Demo
---------------
This script simulates a cybersecurity AI that detects anomalies
in server activity logs and alerts the IT team.

Features:
- Reads infrastructure log data
- Uses anomaly detection (Isolation Forest)
- Sends security alerts when suspicious behaviour is detected
"""

import pandas as pd
from sklearn.ensemble import IsolationForest


# -------------------------------------------------
# 1. Load log data
# -------------------------------------------------

# Read the simulated server logs
logs = pd.read_csv("logs.csv")

print("Loaded logs:")
print(logs)


# -------------------------------------------------
# 2. Train anomaly detection model
# -------------------------------------------------

"""
Isolation Forest is commonly used for anomaly detection.
It works by isolating unusual observations in the dataset.

Normal behaviour = common patterns
Anomaly = rare pattern
"""

model = IsolationForest(
    contamination=0.1,  # expected proportion of anomalies
    random_state=42
)

# Train model
model.fit(logs)


# -------------------------------------------------
# 3. Predict anomalies
# -------------------------------------------------

"""
Prediction output:
1  = normal behaviour
-1 = anomaly
"""

logs["anomaly"] = model.predict(logs)

print("\nAnalysis results:")
print(logs)


# -------------------------------------------------
# 4. Detect security risks
# -------------------------------------------------

alerts = logs[logs["anomaly"] == -1]

print("\nDetected anomalies:")
print(alerts)


# -------------------------------------------------
# 5. Alert IT team
# -------------------------------------------------

def send_alert(row):
    """
    Simulates sending a security alert.
    In real systems this could send:
    - Email
    - Slack message
    - SIEM alert
    """

    print("\n⚠ SECURITY ALERT ⚠")
    print("---------------------")
    print(f"Login attempts: {row['login_attempts']}")
    print(f"Failed logins: {row['failed_logins']}")
    print(f"Data transfer: {row['data_transfer_mb']} MB")
    print("Possible brute-force or abnormal behaviour detected.")
    print("---------------------")


# Send alerts
for _, row in alerts.iterrows():
    send_alert(row)


# -------------------------------------------------
# 6. Summary
# -------------------------------------------------

print("\nMonitoring complete.")