[SecurePortal_Documentation.docx](https://github.com/user-attachments/files/27624521/SecurePortal_Documentation.docx)
[README.md](https://github.com/user-attachments/files/27624335/README.md)
# 🔐 SecurePortal — AI-Powered Zero Trust Authentication System

![Python](https://img.shields.io/badge/Python-3.9-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-black?logo=flask)
![AWS](https://img.shields.io/badge/AWS-EC2%20%7C%20RDS%20%7C%20CloudWatch-orange?logo=amazon-aws)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-RDS-blue?logo=postgresql)
![ML](https://img.shields.io/badge/ML-Scikit--learn-yellow?logo=scikit-learn)
![License](https://img.shields.io/badge/License-MIT-green)

> A production-deployed, cloud-native behavioral biometrics security system that silently evaluates every login attempt using Machine Learning, IP geolocation, and device fingerprinting — automatically triggering MFA or blocking suspicious sessions in real time.

---

## 📸 Live Demo

| Normal Login | Suspicious Login (New Device) | Botnet Attack Detected |
|---|---|---|
| ✅ Allowed instantly | ⚠️ MFA triggered, alert email sent | 🚨 Blocked mid-session, PDF report emailed |

**Live URL:** `http://184.73.70.95:5000`

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      User Browser                        │
│         (Silently collects typing speed, mouse,         │
│          device fingerprint via JavaScript)              │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTPS
                        ▼
┌─────────────────────────────────────────────────────────┐
│              AWS EC2 (Amazon Linux)                      │
│                                                          │
│   ┌──────────────────┐    ┌──────────────────────────┐  │
│   │  Flask App        │───▶│  ML Risk Engine API      │  │
│   │  app.py :5000     │    │  ml_service.py :6000     │  │
│   │                   │    │  (Logistic Regression)   │  │
│   └────────┬─────────┘    └──────────────────────────┘  │
│            │                                             │
└────────────┼─────────────────────────────────────────────┘
             │
     ┌───────┴────────┐
     │                │
     ▼                ▼
┌─────────┐    ┌──────────────┐    ┌───────────────────┐
│ AWS RDS │    │ AWS          │    │ ipapi.co          │
│ Postgres│    │ CloudWatch   │    │ (GeoIP Lookup)    │
│ (Users  │    │ (Forensic    │    │                   │
│  & Auth │    │  Log Stream) │    └───────────────────┘
│  Data)  │    │              │
└─────────┘    └──────────────┘
```

---

## ✨ Features

### 🔍 Behavioral Biometrics
- Silently captures **typing speed (CPM)**, **mouse movement count**, **login hour**
- Compares against the user's own historical profile (personalized ML model)

### 🤖 ML Risk Engine
- **Logistic Regression** model trained on behavioral CSV logs
- Detects automated bot attacks (typing speed > 10,000 CPM = instant block)
- Assigns risk score **0–100** per login

### 🌍 Geolocation & Device Fingerprinting
- Real-time IP geolocation via `ipapi.co`
- Detects impossible travel (location change within 30 minutes)
- Tracks OS + Browser fingerprint — flags new device logins

### 🛡️ Zero Trust Risk Actions
| Risk Score | Action |
|---|---|
| 0 – 39 | ✅ Login Allowed |
| 40 – 69 | ⚠️ MFA Required — OTP sent to email with device details |
| 70 – 100 | 🚨 Account Blocked 24hrs + Forensic PDF emailed |

### 📧 Smart Alerts
- **MFA Email** includes: Location, OS, Browser, IP Address, Timestamp (IST)
- **Forensic PDF Report** (ReportLab): Full threat analysis, risk breakdown, actions taken
- Suspicious logins **never corrupt** the trusted device profile

### ☁️ AWS CloudWatch Integration
- All events streamed in real-time to Log Group: `SecurePortal/RiskEngine`
- Structured severity levels: `INFO` → `WARNING` → `CRITICAL`
- Zero hardcoded credentials — uses IAM Instance Role

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python, Flask |
| **ML Engine** | Scikit-learn (Logistic Regression) |
| **Database** | AWS RDS PostgreSQL (psycopg2) |
| **Compute** | AWS EC2 (Amazon Linux 2) |
| **Logging** | AWS CloudWatch (boto3 + watchtower) |
| **Auth (AWS)** | IAM Instance Role (keyless) |
| **PDF Reports** | ReportLab |
| **Email** | Flask-Mail (Gmail SMTP) |
| **GeoIP** | ipapi.co REST API |
| **Frontend** | HTML, CSS, JavaScript (telemetry collection) |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.9+
- AWS Account with EC2, RDS, CloudWatch access
- Gmail account with App Password enabled

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/secureportal.git
cd secureportal
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
pip install -r requirements_ml.txt
```

### 3. Configure Environment Variables
Create a `.env` file in the project root:
```env
FLASK_SECRET_KEY=your-secret-key

MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password

DB_HOST=your-rds-endpoint.rds.amazonaws.com
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=your-db-password
DB_PORT=5432
```

### 4. Run Locally
```bash
# Terminal 1 — Start ML Risk Engine
python ml_service.py

# Terminal 2 — Start Flask App
python app.py
```

### 5. Deploy to AWS EC2
```bash
# Copy files to EC2
scp -i riskkey.pem app.py ml_service.py .env ec2-user@your-ec2-ip:~/

# SSH into EC2 and start services
ssh -i riskkey.pem ec2-user@your-ec2-ip
bash run.sh
```

---

## ☁️ AWS Setup Guide

### EC2
1. Launch `t2.micro` Amazon Linux 2 instance
2. Security Group: Open port `5000` (public), `22` (your IP only)
3. Attach IAM Role with `CloudWatchLogsFullAccess`

### RDS PostgreSQL
1. Create `db.t3.micro` PostgreSQL instance
2. Security Group: Allow port `5432` from EC2 Security Group only
3. Update `.env` with RDS endpoint

### CloudWatch
1. No setup needed — log group `SecurePortal/RiskEngine` auto-created on first run
2. View logs: AWS Console → CloudWatch → Log Management → SecurePortal/RiskEngine

### IAM Role (Keyless Auth)
1. Create role: `SecurePortal-CloudWatch-Role`
2. Attach policy: `CloudWatchLogsFullAccess`
3. Attach role to EC2 instance as Instance Profile

---

## 📊 CloudWatch Log Examples

```
INFO  | TELEMETRY LOG: Alby,156,213,10,0.0,0.0,0
INFO  | ====== LIVE TELEMETRY CAPTURED ======
INFO  | User         : Alby
INFO  | Location     : Kochi, Kerala, India
INFO  | OS/Browser   : Windows / Chrome
INFO  | Typing Speed : 156 cpm
INFO  | Mouse Moves  : 213
INFO  | =====================================
WARN  | ACTION: MFA_REQUIRED (Risk: 40)
CRIT  | 🚨 ACTION: KICKING USER Alby MID-SESSION
CRIT  | MID-SESSION LOCKOUT: User Alby locked until 2026-04-29T10:23:46
```

---

## 🎯 Demo Flow (Presentation)

1. **Register** a new user → stored in AWS RDS
2. **Login normally** → Allowed, telemetry logged to CloudWatch
3. **Share credentials** with a friend on a different OS/Browser → MFA triggered, alert email sent with device fingerprint
4. **Trigger Botnet Trap** on dashboard → mid-session block, 24hr lockout, forensic PDF emailed
5. **Show CloudWatch** → live security logs streaming in real time

---

## 📁 Project Structure

```
secureportal/
├── app.py                  # Main Flask application & risk routing
├── ml_service.py           # Standalone ML Risk Engine API (port 6000)
├── run.sh                  # Production startup script
├── training_data.csv       # Behavioral telemetry log (ML training data)
├── requirements.txt        # Flask app dependencies
├── requirements_ml.txt     # ML service dependencies
├── .env                    # Environment secrets (never commit)
├── templates/
│   ├── login.html          # Login page (telemetry collection)
│   ├── dashboard.html      # User dashboard + Botnet Trap
│   ├── register.html       # Registration page
│   └── mfa.html            # OTP verification page
└── test_rds_connection.py  # RDS connectivity test script
```

---

## 🔒 Security Notes

- Never commit `.env` to Git — add it to `.gitignore`
- Use IAM Roles instead of hardcoded AWS credentials
- RDS is not publicly accessible — EC2-only access
- Suspicious logins never update the trusted device profile (prevents context poisoning)

---

## 📄 License

This project is licensed under the MIT License.

---

## 👤 Author

**Sebastian Sojan**
- Built as a college final year project
- Deployed on AWS EC2 with full cloud integration

---

*"Anywhere a username and password exists, SecurePortal sits invisibly behind it — making it 10x more secure without changing the user experience."*
