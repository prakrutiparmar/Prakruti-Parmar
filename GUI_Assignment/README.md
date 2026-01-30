# 🛡️ GUI Assignment – SOC Log Analysis Dashboard

This project is a **GUI-based SOC-style forensic log analysis dashboard** developed as part of my internship assignment.  
It visualizes forensic findings from system logs using a **FastAPI backend** and a **Streamlit-based frontend**.

---
## 🌐 Live Demo

👉 **[Open the live SOC dashboard](https://log-analysis-gui-prakruti.streamlit.app/)**

---

## 🎯 Objective

The objective of this assignment is to:

- Present forensic log analysis results in a **clear SOC-style dashboard**
- Enable **case-based investigation**
- Allow analysts to **download investigation reports**
- Demonstrate understanding of **security events, timelines, and MITRE ATT&CK techniques**

---

## 🏗️ Project Structure

```
GUI_Assignment/
├── app.py # FastAPI backend (JSON APIs)
├── sgui.py # Streamlit GUI dashboard
├── data/ # Log files used for analysis
├── analysis_reports/ # Generated audit reports (MD / PDF)
└── README.md # Project documentation
```

---

## Features

✔ Case-based forensic analysis  
✔ Live API-driven dashboard  
✔ SOC-style threat visualization  
✔ Detection summary with severity levels  
✔ Risk score per analyzed file  
✔ Timeline reconstruction with heatmap  
✔ MITRE ATT&CK technique mapping  
✔ Execution artifact visualization  
✔ Downloadable investigation reports

---

## 📊 Detection Categories

The dashboard evaluates logs for:

- **Credential Access**
- **Privilege Escalation**
- **Suspicious PowerShell Activity**
- **Persistence / Network Indicators**

Each category is displayed with a **severity indicator**:

- 🟢 LOW
- 🟡 MEDIUM
- 🔴 HIGH

---

## 🧭 Severity Legend

| Severity  | Meaning                      |
| --------- | ---------------------------- |
| 🟢 LOW    | Benign / expected activity   |
| 🟡 MEDIUM | Suspicious behavior detected |
| 🔴 HIGH   | Confirmed malicious activity |

---

## 🎯 MITRE ATT&CK Mapping

Detected behaviors are mapped to relevant MITRE ATT&CK techniques such as:

- `T1059` – Command and Scripting Interpreter
- `T1003` – Credential Dumping
- `T1547` – Boot or Logon Autostart Execution

---

## 🕒 Timeline Analysis

- Event timeline reconstructed from log sources
- Hour-based **timeline heatmap** to identify activity spikes

---

## 📄 Investigation Reports

- For each analyzed log file, a corresponding audit report is available
- Reports are stored in `analysis_reports/`
- Users can download reports directly from the GUI

---

## ▶️ How to Run

### 1️⃣ Start the API

```bash
uvicorn app:app --reload
```
