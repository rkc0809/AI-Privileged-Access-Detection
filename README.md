# AI-Powered SOC Threat Detection Pipeline

## Overview

This project simulates a **Security Operations Center (SOC) detection pipeline** that analyzes login activity, detects suspicious behavior, enriches alerts with threat intelligence, and correlates attack signals to generate incident reports.

The system demonstrates how modern SOC platforms automate **threat detection, investigation, and response workflows**.

---

## Key Features

* Login activity simulation
* Behavioral anomaly detection
* Risk scoring engine
* Threat intelligence enrichment
* Attack pattern detection
* Attack campaign detection
* Incident correlation engine
* AI-based incident analysis
* Automated SOC pipeline

---

## Project Architecture

```
Log Generator
      ↓
Anomaly Detection
      ↓
Alert Engine
      ↓
Investigation Agent
      ↓
Threat Intelligence
      ↓
Attack Pattern Detection
      ↓
Attack Campaign Detection
      ↓
Risk Scoring Engine
      ↓
Correlation Engine
      ↓
AI SOC Analyst
      ↓
Incident Report Generator
```

---

## Attack Scenarios Detected

### Brute Force Attack

Multiple failed login attempts targeting a single account.

### Credential Stuffing

A single IP address attempting multiple user accounts.

### Suspicious Foreign Login

Login attempt originating from an unusual geographic location.

### Malicious IP Detection

Threat intelligence identifies attacker infrastructure.

### Attack Campaign Detection

Multiple coordinated attacks from the same source IP.

---

## Example Detection Output

```
ATTACK CAMPAIGN DETECTED
Source IP: 45.22.11.90
Users Targeted: 4
Failed Attempts: 18
Attack Type: Credential Stuffing
Severity: CRITICAL
```

---

## Technologies Used

* Python
* Pandas
* Machine Learning (Isolation Forest)
* Threat Intelligence APIs
* Security Detection Engineering Concepts

---

## How to Run

Navigate to the scripts directory and run:

```
python soc_pipeline.py
```

The system will automatically execute the entire SOC detection pipeline.

---

## Learning Outcomes

This project demonstrates practical cybersecurity skills including:

* Security log analysis
* Detection engineering
* Threat intelligence enrichment
* Attack correlation
* Security automation
* SOC investigation workflows
