from flask import Flask, render_template, request, redirect, session, jsonify, make_response
import sqlite3
import os
import requests
import os
import threading
from datetime import datetime
try:
    from dotenv import load_dotenv
    import pathlib
    _env_path = pathlib.Path(__file__).parent / ".env"
    load_dotenv(dotenv_path=_env_path)
except ImportError:
    pass  # dotenv not installed, fall back to system env vars
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

app = Flask(__name__)
from flask_cors import CORS
CORS(app)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "fallback-dev-key-change-in-prod")

# ================= MAIL CONFIG =================
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'dummy@example.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'dummy-password')
app.config['MAIL_DEFAULT_SENDER'] = ('Security Team', app.config['MAIL_USERNAME'])
mail = Mail(app)

import random

# Helper function to generate PDF and send email asynchronously
def send_security_alert_async(app_instance, username, email, risk_score, breakdown, is_blocked=False, metadata=None):
    if risk_score < 40:
        return # Only send reports for MFA or Blocked events
        
    with app_instance.app_context():
        try:
            timestamp = int(datetime.now().timestamp())
            pdf_path = f"security_forensic_{username}_{timestamp}.pdf"
            c = canvas.Canvas(pdf_path, pagesize=letter)
            from reportlab.lib import colors
            
            # --- HEADER SECTION ---
            header_color = colors.HexColor('#020504') # Deep Forest Black
            c.setFillColor(header_color)
            c.rect(0, 720, 612, 80, fill=1, stroke=0)
            
            c.setFillColor(colors.white)
            c.setFont("Helvetica-Bold", 22)
            c.drawString(40, 760, "SECUREPORTAL: FORENSIC SECURITY ANALYSIS")
            c.setFont("Helvetica", 9)
            c.drawString(40, 745, "BEHAVIORAL BIOMETRICS & THREAT INTELLIGENCE DIVISION")
            c.drawString(40, 732, f"REPORT ID: BB-{timestamp} | STATUS: {'CRITICAL' if is_blocked else 'ELEVATED'}")

            # --- CASE INFORMATION ---
            c.setFillColor(colors.black)
            c.setFont("Helvetica-Bold", 11)
            c.drawString(40, 690, "CASE DETAILS")
            c.setStrokeColor(colors.HexColor('#10b981')) # Emerald Green
            c.setLineWidth(1)
            c.line(40, 685, 570, 685)
            
            c.setFont("Helvetica", 10)
            c.drawString(50, 665, f"Target Account: {username}")
            c.drawString(50, 650, f"Account Email: {email}")
            c.drawString(50, 635, f"Timestamp (UTC): {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            if metadata:
                c.drawString(300, 665, f"IP Address: {metadata.get('ip', 'Unknown')}")
                c.drawString(300, 650, f"Geo-Location: {metadata.get('location', 'Unknown Country')}")
                c.drawString(300, 635, f"Device ID: {metadata.get('user_agent', 'Generic Browser')[:40]}...")

            # --- THREAT ANALYSIS ---
            c.setFont("Helvetica-Bold", 11)
            c.drawString(40, 600, "THREAT DECOMPOSITION")
            c.line(40, 595, 570, 595)
            
            # Risk Meter
            risk_color = colors.HexColor('#ef4444') if is_blocked else colors.HexColor('#f59e0b')
            c.setFillColor(risk_color)
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, 575, f"AGGREGATE THREAT METRIC: {risk_score} / 100")
            
            c.setFillColor(colors.black)
            c.setFont("Helvetica", 10)
            y = 550
            c.drawString(60, y, f"► Machine Learning Anomaly Detection (Z-Score Deviation):")
            c.drawRightString(500, y, f"{breakdown.get('ml_risk', 0)}")
            c.drawString(60, y-15, f"► Geographic Inconsistency / Impossible Travel Force:")
            c.drawRightString(500, y-15, f"{breakdown.get('travel_risk', 0)}")
            c.drawString(60, y-30, f"► Hardware Fingerprint Discrepancy:")
            c.drawRightString(500, y-30, f"{breakdown.get('device_risk', 0)}")
            c.drawString(60, y-45, f"► Temporal Access Pattern Anomaly:")
            c.drawRightString(500, y-45, f"{breakdown.get('time_risk', 0)}")

            # --- INCIDENT SUMMARY ---
            c.setFont("Helvetica-Bold", 11)
            c.drawString(40, 470, "EXECUTIVE ANALYSIS")
            c.line(40, 465, 570, 465)
            
            summary_box_color = colors.HexColor('#fff1f2') if is_blocked else colors.HexColor('#fffbeb')
            c.setFillColor(summary_box_color)
            c.rect(40, 390, 530, 65, fill=1, stroke=1)
            
            c.setFillColor(colors.black)
            c.setFont("Helvetica-Bold", 10)
            title = "CRITICAL: UNAUTHORIZED ACCESS ATTEMPT BLOCKED" if is_blocked else "WARNING: UNUSUAL ACTIVITY DETECTED"
            c.drawString(55, 435, title)
            
            c.setFont("Helvetica", 9)
            if is_blocked:
                text = "The SecurePortal Defensive Core identifies this session as highly malicous. The behavioral fingerprint does not match the established biometric profile. Access has been severed and the account has been placed in a 24-hour lockdown."
            else:
                text = "Significant deviations from your typical usage patterns were detected. While credentials matched, the biometric interaction was inconsistent with your baseline. Multi-Factor Authentication was successfully mandated."
            
            # Basic text wrapping
            words = text.split()
            lines = []
            curr_line = ""
            for w in words:
                if len(curr_line + w) < 95: curr_line += w + " "
                else: lines.append(curr_line); curr_line = w + " "
            lines.append(curr_line)
            
            ty = 422
            for line in lines:
                c.drawString(55, ty, line)
                ty -= 12

            # --- REMEDIATION STEPS ---
            c.setFont("Helvetica-Bold", 11)
            c.drawString(40, 350, "REMEDIATION & RECOVERY STEPS")
            c.line(40, 345, 570, 345)
            
            c.setFont("Helvetica", 10)
            c.drawString(50, 325, "If this was NOT you, please follow these priority steps immediately:")
            c.setFont("Helvetica-Bold", 10)
            c.drawString(70, 305, "1. RESET YOUR PASSWORD: Change your SecurePortal password to a unique, strong value.")
            c.drawString(70, 290, "2. AUDIT RECENT ACTIVITY: Check your profile for any unauthorized changes.")
            c.drawString(70, 275, "3. CONTACT SECURITY: If you believe your identity is compromised, email sec-ops@secureportal.com.")
            
            # --- FOOTER ---
            c.setFont("Helvetica-Oblique", 8)
            c.setFillColor(colors.gray)
            c.drawString(40, 40, "This is an automated system-generated report. Do not reply to this email.")
            c.drawRightString(570, 40, "Emerald Nocturne Defensive Platform v2.0")
            
            c.save()
            
            # Email Setup
            subject = f"[ALERT] Security Incident: {username}" if is_blocked else f"[Security Notice] Unusual Login Attempt: {username}"
            body = f"Hi {username},\n\nOur behavioral risk system has detected { 'an unauthorized' if is_blocked else 'unusual' } activity on your account. A detailed forensic investigation report is attached to this email.\n\nACTION REQUIRED: Please review the remediation steps in the report if you did not initiate this login.\n\nBest regards,\nSecurePortal Security Operations"
            
            msg = Message(subject=subject, recipients=[email], body=body)
            with open(pdf_path, "rb") as fp:
                msg.attach(pdf_path, "application/pdf", fp.read())
            mail.send(msg)
            print(f"Forensic Report Sent to {username}!")
            os.remove(pdf_path)
        except Exception as e:
            print(f"Forensic PDF Error: {e}")

# Helper function to send MFA email
def send_mfa_email_async(app_instance, username, email, code):
    with app_instance.app_context():
        try:
            msg = Message(
                subject="SecurePortal: Your Verification Code",
                recipients=[email],
                body=f"Hi {username},\n\nYour 6-digit verification code is: {code}\n\nPlease enter this on the portal to continue.\n\nSecurity Team"
            )
            mail.send(msg)
            print(f"MFA Code sent to {username}!")
        except Exception as e:
            print(f"Failed to send MFA email: {e}")

# ================= DATABASE =================
def get_db():
    return sqlite3.connect("users.db")

# -------- USERS TABLE --------
with get_db() as conn:
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT,
        password TEXT,
        locked_until TEXT
    )
    """)

# -------- LOGIN CONTEXT TABLE --------
with get_db() as conn:
    conn.execute("""
    CREATE TABLE IF NOT EXISTS login_context (
        username TEXT PRIMARY KEY,
        last_location TEXT,
        last_login_time TEXT,
        last_device TEXT
    )
    """)

# ================= AUTH =================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        is_ajax = request.is_json
        username = request.json.get("username") if is_ajax else request.form.get("username")
        password = request.json.get("password") if is_ajax else request.form.get("password")

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )
        user = cur.fetchone()

        # user[4] is the locked_until column
        if user and user[4]:
            unlock_time = datetime.fromisoformat(user[4])
            if datetime.now() < unlock_time:
                if is_ajax:
                    return jsonify({"status": "locked", "message": "Account Locked for 24h due to suspicious activity."}), 403
                return "Account Locked for 24h due to suspicious activity."

        # user[2] is the hashed password in the database
        if user and check_password_hash(user[2], password):
            if session.get("user") != username:
                session.pop("mfa_pending", None)
                session.pop("mfa_code", None)
                session.pop("last_risk", None)
                
            session["user"] = username
            login_time = datetime.now().isoformat()

            conn.execute("""
                INSERT OR REPLACE INTO login_context (username, last_login_time)
                VALUES (?, ?)
            """, (username, login_time))
            conn.commit()

            if is_ajax:
                return jsonify({"status": "success"})
            return redirect("/dashboard")
        else:
            if is_ajax:
                return jsonify({"status": "error", "message": "Invalid credentials"}), 401
            return "Invalid credentials"

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        try:
            hashed_password = generate_password_hash(password)
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                (username, hashed_password, email)
            )
            conn.commit()
            return redirect("/")
        except:
            return "User already exists"

    return render_template("register.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    if session.get("mfa_pending"):
        return redirect("/mfa")
    
    risk = session.get("last_risk", 0)
    response = make_response(render_template("dashboard.html", user=session["user"], risk=risk))
    
    # Prevent browser caching
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    
    return response

@app.route("/mfa")
def mfa():
    if "user" not in session or not session.get("mfa_pending"):
        return redirect("/")
    return render_template("mfa.html")

@app.route("/verify_mfa", methods=["POST"])
def verify_mfa():
    if "user" not in session or not session.get("mfa_pending"):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    data = request.get_json()
    code = data.get("code")
    
    if code and code == session.get("mfa_code"):
        session.pop("mfa_pending", None)
        session.pop("mfa_code", None)
        session["last_risk"] = 0  # Reset risk slate after successful verification
        return jsonify({"status": "success"})
        
    return jsonify({"status": "error", "message": "Verification failed. Incorrect code."}), 400

@app.route("/resend_mfa", methods=["POST"])
def resend_mfa():
    if "user" not in session or not session.get("mfa_pending"):
        return jsonify({"status": "error"}), 401
        
    username = session["user"]
    code = session.get("mfa_code")
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE username=?", (username,))
    urow = cur.fetchone()
    user_email = urow[0] if urow and urow[0] else f"{username}@example.com"
    
    email_thread = threading.Thread(
        target=send_mfa_email_async,
        args=(app, username, user_email, code)
    )
    email_thread.start()
    return jsonify({"status": "success"})

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")

# ================= BEHAVIOR & RISK ENGINE =================
# ================= BEHAVIOR & RISK ENGINE =================
@app.route("/behavior", methods=["POST"])
def behavior():

    if "user" not in session:
        return jsonify({"status": "unauthorized"}), 401

    data = request.get_json()
    user_agent = data.get("user_agent", "")
    username = session["user"]
    
    # Notice how we completely removed the internal sqlite3 logic to track travel history here.
    # The "Dumb Client" model means the cloud API handles all historical context!

    # -------- LOG TELEMETRY FOR TRAINING --------
    import csv
    import os
    from datetime import datetime
    try:
        csv_path = "training_data.csv"
        write_header = not os.path.exists(csv_path)
        with open(csv_path, "a", newline="") as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow(["username", "typing_speed", "mouse_moves", "login_hour", "is_bot"])
            writer.writerow([
                username,
                data.get("typing_speed", 0), 
                data.get("mouse_moves", 0), 
                datetime.now().hour,
                0 # Default to 0 (authentic user)
            ])
    except Exception as e:
        print("Failed to append to training_data.csv:", e)

    # -------- CALL ML RISK ENGINE SERVICE --------
    try:
        # Pass minimal raw telemetry. 
        # The API doesn't need to be told when the last login was; it looks it up using the API Key!
        api_payload = {
            "username": username,
            "user_agent": user_agent,
            "ip_address": data.get("ip_address", ""), 
            "typing_speed": data.get("typing_speed", 0),
            "mouse_moves": data.get("mouse_moves", 0)
        }

        # Multi-Tenant Authentication Header
        headers = {
            "Authorization": "Bearer test-api-key-123"
        }

        # Call the standalone Risk API
        ml_response = requests.post(
            "http://127.0.0.1:5001/evaluate",
            json=api_payload,
            headers=headers,
            timeout=3
        )

        if ml_response.status_code == 200:
            result = ml_response.json()
            
            total_risk = result.get("total_risk", 0)
            action = result.get("action", "allowed")
            session["last_risk"] = total_risk
            
            # Prevent Bypass: If they already have a pending MFA, force it so they can't clear it via a slow login
            if session.get("mfa_pending"):
                print(f"ACTION: MFA_REQUIRED (Forced due to pending state) — resending OTP")
                # Fetch email and resend OTP so user doesn't get stuck without a code
                conn = get_db()
                cur = conn.cursor()
                cur.execute("SELECT email FROM users WHERE username=?", (username,))
                urow = cur.fetchone()
                user_email = urow[0] if urow and urow[0] and "@" in urow[0] else f"{username}@example.com"
                
                code = str(random.randint(100000, 999999))
                session["mfa_code"] = code
                
                email_thread = threading.Thread(
                    target=send_mfa_email_async,
                    args=(app, username, user_email, code)
                )
                email_thread.start()
                return jsonify({"status": "mfa_required", "risk": total_risk})
            
            print(f"Risk Engine Breakdown: {result.get('breakdown')}")
            print(f"ACTION: {action.upper()} (Risk: {total_risk})")
            
            # Fetch actual email
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT email FROM users WHERE username=?", (username,))
            urow = cur.fetchone()
            user_email = urow[0] if urow and urow[0] else f"{username}@example.com"

            # -------- CONDITIONAL REPORTING: TRIGGER PDF ONLY FOR RISKS >= 40 --------
            breakdown = result.get('breakdown', {})
            metadata = {
                "ip": data.get("ip_address"),
                "location": result.get("location", "Unknown"), # We'll ensure API returns this
                "user_agent": user_agent
            }
            
            if total_risk >= 40:
                email_thread = threading.Thread(
                    target=send_security_alert_async,
                    args=(app, username, user_email, total_risk, breakdown, action == "blocked", metadata)
                )
                email_thread.start()

            if action == "blocked":
                session.pop("user", None)
                
                # SET LOCKOUT (Phase 7)
                from datetime import timedelta
                locked_until = (datetime.now() + timedelta(hours=24)).isoformat()
                conn = get_db()
                conn.execute("UPDATE users SET locked_until=? WHERE username=?", (locked_until, username))
                conn.commit()
                print(f"LOCKOUT ENABLED: User {username} locked until {locked_until}")
                
            elif action == "mfa_required":
                # Generate a 6-digit OTP code
                code = str(random.randint(100000, 999999))
                session["mfa_code"] = code
                session["mfa_pending"] = True
                
                email_thread = threading.Thread(
                    target=send_mfa_email_async,
                    args=(app, username, user_email, code)
                )
                email_thread.start()
            
            return jsonify({"status": action, "risk": total_risk})
        else:
            print(f"API Error: {ml_response.text}")

    except Exception as e:
        print("Risk Engine API unavailable:", e)
        # Fail open or fail closed logic here depending on business needs
        return jsonify({"status": "allowed", "risk": 0})
        
    return jsonify({"status": "allowed", "risk": 0})

# ================= ACTIVE DASHBOARD TELEMETRY =================
@app.route("/active_behavior", methods=["POST"])
def active_behavior():
    if "user" not in session:
        return jsonify({"status": "unauthorized"}), 401

    data = request.get_json()
    current_time = datetime.now()
    
    # Simple risk additive logic for mid-session
    active_risk = 0
    
    # 1. Did they type too fast? (Bot simulation/Pasting)
    typing_speed = data.get("typing_speed", 0)
    if typing_speed > 1500: # impossibly fast typing (pasting text or bot)
        active_risk += 30
        print(f"ACTIVE FLAG: Suspicious typing speed detected ({typing_speed} cpm)")
        
    # 2. Are they moving the mouse at all while typing fast?
    mouse_moves = data.get("mouse_moves", 0)
    if typing_speed > 600 and mouse_moves == 0:
        active_risk += 15
        print(f"ACTIVE FLAG: Zero mouse movement during high typing speed")

    # Skip ML Service for active_behavior because the ML model is trained on
    # full-session data, not 10-second snapshots. Applying it here causes
    # high false positive rates.

    # Add to baseline session risk
    baseline_risk = session.get("last_risk", 0)
    total_risk = baseline_risk + active_risk
    
    # Cap at 100
    total_risk = min(total_risk, 100)
    session["last_risk"] = total_risk
    
    print(f"MID-SESSION UPDATE - User: {session['user']} | Active Risk Spike: +{active_risk} | Total Risk: {total_risk}")

    # Kick if too high
    if total_risk >= 70:
        username = session['user']
        print(f"🚨 ACTION: KICKING USER {username} MID-SESSION")
        session.pop("user", None)
        
        # Trigger the Post-Block Email Notification for Dashboard Suspension
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT email FROM users WHERE username=?", (username,))
            urow = cur.fetchone()
            user_email = urow[0] if urow and urow[0] else f"{username}@example.com"
            
            # SET LOCKOUT (Phase 7)
            from datetime import timedelta
            locked_until = (datetime.now() + timedelta(hours=24)).isoformat()
            conn.execute("UPDATE users SET locked_until=? WHERE username=?", (locked_until, username))
            conn.commit()
            print(f"MID-SESSION LOCKOUT: User {username} locked until {locked_until}")

            # Trigger Forensic Report for Mid-Session Block
            breakdown = {
                "device_risk": 0,
                "travel_risk": 0,
                "time_risk": 0,
                "ml_risk": active_risk
            }
            metadata = {
                "ip": data.get("ip_address", "Internal Network"),
                "user_agent": request.headers.get('User-Agent', 'Dashboard Session')
            }
            email_thread = threading.Thread(
                target=send_security_alert_async,
                args=(app, username, user_email, total_risk, breakdown, True, metadata)
            )
            email_thread.start()
        except Exception as e:
            print("Failed to dispatch active-session email:", e)
            
        return jsonify({"status": "blocked", "risk": total_risk})

    elif total_risk >= 40:
        username = session.get('user')
        if username:
            print(f"⚠️ ACTION: TRIGGERING MFA FOR {username} MID-SESSION")
            code = str(random.randint(100000, 999999))
            session["mfa_code"] = code
            session["mfa_pending"] = True
            
            try:
                conn = get_db()
                cur = conn.cursor()
                cur.execute("SELECT email FROM users WHERE username=?", (username,))
                urow = cur.fetchone()
                user_email = urow[0] if urow and urow[0] else f"{username}@example.com"
                
                email_thread = threading.Thread(
                    target=send_mfa_email_async,
                    args=(app, username, user_email, code)
                )
                email_thread.start()
            except Exception as e:
                print("Failed to dispatch active-session MFA email:", e)
                
        return jsonify({"status": "mfa_required", "risk": total_risk})

    return jsonify({"status": "allowed", "risk": total_risk})


# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=False)
