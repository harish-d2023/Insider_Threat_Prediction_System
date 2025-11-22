# Insider_Threat_Prediction_System - Python (Tkinter GUI)

A fully functional **Insider Threat Prediction System**, implemented as a **single-file Python application**, designed for **internship, academic, and cybersecurity portfolio projects**.  
The project demonstrates how insider risk monitoring, event simulation, AI-based risk scoring, sentiment analysis, automated incident response, case management, and gamification can be integrated into a **Tkinter-based SOC dashboard — without any external dependencies**.

---

## 📸 Screenshot
  
```
![Dashboard Screenshot](screenshots/Screenshot%202025-11-22%20214100.png)

```

---

## ✨ System Highlights

| Area | Features |
|------|---------|
| User/Activity Monitoring | Real-time event simulation, anomaly detection |
| AI Risk Modeling | Weighted scoring, sentiment inversion, explainable risk |
| NLP Sentiment Analysis | Lexicon-based polarity & emotion scoring |
| Automated SOC Response | Auto-remediation, isolation, notifications |
| SOC Dashboard | Live alerts, KPIs, visualization charts, audit logs |
| Case Management | Case history, assignment, closure, CSV export |
| Gamification | Sandbox challenges, leaderboard, analyst badges |
| No Dependencies | Works offline with **standard Python modules only** |

---

## 📌 Full Feature Breakdown

### 🔹 1. **Real-Time Threat Simulation**
The system generates simulated user events such as:
- Off-hours activity  
- USB / removable media access  
- Unusual process execution  
- Bulk file downloads  
- Suspicious messages (via sentiment scoring)

Each event → analyzed → risk scored → converted into an alert → shown on the dashboard.

---

### 🔹 2. **AI-Driven Risk Prediction**
The `compute_risk()` engine performs:
- Weighted feature scoring
- Anomaly amplification
- Sentiment inversion logic
- Score normalization (0–1 scale)
- Explainability breakdown showing contributing factors

Outputs include:
| Output Type | Description |
|-------------|-------------|
| Score (0–1) | Numerical probability of insider risk |
| Score % | Human-readable severity |
| Explanation | Factors that increased/decreased risk |

---

### 🔹 3. **Sentiment Analysis Engine**
A built-in lexicon-based sentiment analyzer scores user communication.  
Used for:
- Inbox analyzer
- Alert generation
- Risk prediction model

---

### 🔹 4. **Automated Incident Response**
If auto-remediation is enabled, the system supports:
| Trigger | Action |
|---------|--------|
| High risk score | Auto-isolation of user |
| Repeated anomalies | Auto case creation |
| New alert | Case assignment + mailto notification |
| Case resolution | Analyst points and badges |

All operations are recorded in the **Audit Log**.

---

### 🔹 5. **Dashboard & Visualization**
The Tkinter dashboard displays:
- KPI Cards: *New Alerts | Avg Score | Open Cases*
- Live Alerts Table
- Real-time bar chart visualization
- Recent audit log activity

---

### 🔹 6. **Case Management**
Analysts can:
- Inspect alerts
- Convert alerts to cases
- Assign analysts
- Close cases
- Export case list to CSV

---

### 🔹 7. **Gamification & Sandbox**
A cybersecurity training layer that includes:
- Leaderboard (analyst score tracking)
- Badge rewards
- Sandbox training mode (5 alerts per round)
- Points awarded for correct decisions

---

### 🔹 8. **Configurable Settings**
Includes:
- Auto-remediation toggle
- Risk score threshold configuration
- Open external policy documentation

---

## 📂 Project Structure

```
.
└── insider_threat_system.py   # Main single-file application
```

---

## ⚙️ How to Run

### 1️⃣ Install Python (if not already installed)
Download Python 3.10+ from:  
➡ https://www.python.org/downloads/

Make sure to check:  
✔ `Add Python to PATH`

---

### 2️⃣ Execute the Application
Open **CMD / PowerShell / Terminal** in the project directory and run:

```sh
python insider_threat_system.py
```

The Tkinter dashboard will launch automatically.

---

## 📦 Built-In Python Modules Used (No external installation required)

```
tkinter, ttk, messagebox, font
datetime, timedelta
random, time
webbrowser
csv, os
```

> 💡 Works fully **offline** — no `pip install` commands required.

---

## 🧠 System Architecture Overview

```
+------------------------------+
|   Tkinter GUI Application    |
+-------------+----------------+
              |
              v
+------------------------------+
|  Event Generator / Simulator |
+------------------------------+
              |
              v
+------------------------------+
|    Risk Prediction Engine    |
|  compute_risk(features)      |
+------------------------------+
              |
              v
+------------------------------+
|     Alert Generation Layer   |
+------------------------------+
              |
              v
+------------------------------+
|  Dashboard / Visualizations  |
|  KPIs | Alerts | Charts      |
+------------------------------+

Supporting Modules:
- Case Management
- Sentiment Inbox
- Gamification
- Automated Actions Engine
```

---

## 🏁 Ideal Use Cases
- Internship / CV / Portfolio Projects
- Academic IEEE Research / Final-Year Projects
- Cybersecurity Learning & Demonstrations
- SOC Analyst Training Simulations

---


## 📜 Disclaimer
This software is intended for **education, simulation, and research purposes only**.  
It is **not** a replacement for enterprise-grade insider threat monitoring tools.

---

### ⭐ If you find this project helpful, please consider giving it a star on GitHub!
