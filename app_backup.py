from flask_cors import CORS
import requests
from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
from datetime import datetime

app = Flask(__name__)
CORS(app)
app.secret_key = "secret123"

# ================= DATABASE =================
def get_db():
    return sqlite3.connect("users.db")

# -------- USERS TABLE --------
with get_db() as conn:
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
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
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        )
        user = cur.fetchone()

        if user:
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
        password = request.form["password"]

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
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
    risk = session.get("last_risk", 0)
    return render_template("dashboard.html", user=session["user"], risk=risk)

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
    user_agent = data.get("user_agent", "").lower()

    # -------- DEVICE DETECTION --------
    os = "Windows" if "windows" in user_agent else "MacOS" if "mac" in user_agent else "Other"
    browser = "Chrome" if "chrome" in user_agent else "Firefox" if "firefox" in user_agent else "Other"
    device = f"{browser}-{os}"

    # -------- LOCATION DETECTION --------
    location = "Unknown"
    try:
        res = requests.get("https://ipapi.co/json/", timeout=3)
        if res.status_code == 200:
            location = res.json().get("country_name", "Unknown")
    except:
        pass

    current_time = datetime.now()

    # -------- LOGIN TIME RISK --------
    login_time_risk = 10 if current_time.hour < 6 or current_time.hour > 22 else 0

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT last_location, last_login_time, last_device
        FROM login_context
        WHERE username = ?
    """, (session["user"],))

    row = cur.fetchone()

    last_location = row[0] if row else None
    last_time = datetime.fromisoformat(row[1]) if row and row[1] else None
    last_device = row[2] if row else None

    # -------- IMPOSSIBLE TRAVEL --------
    impossible_travel = False
    travel_risk = 0

    if last_location and last_time:
        diff_minutes = (current_time - last_time).total_seconds() / 60
        if last_location != location and diff_minutes < 30:
            impossible_travel = True
            travel_risk = 30

    # -------- NEW DEVICE FLAG --------
    new_device = False
    device_risk = 0

    if last_device and last_device != device:
        new_device = True
        device_risk = 20

    # -------- UPDATE CONTEXT --------
    conn.execute("""
        INSERT OR REPLACE INTO login_context
        (username, last_location, last_login_time, last_device)
        VALUES (?, ?, ?, ?)
    """, (session["user"], location, current_time.isoformat(), device))
    conn.commit()

    # ================= ML SERVICE CALL =================
    ml_risk = 0
    try:
        ml_payload = {
            "typing_speed": data.get("typing_speed", 0),
            "mouse_moves": data.get("mouse_moves", 0),
            "login_hour": current_time.hour,
            "new_device": 1 if new_device else 0,
            "location_change": 1 if last_location and last_location != location else 0
        }

        # -------- DATA COLLECTION FOR CUSTOM MODEL --------
        import csv
        import os
        try:
            csv_path = "training_data.csv"
            write_header = not os.path.exists(csv_path)
            with open(csv_path, "a", newline="") as f:
                writer = csv.writer(f)
                if write_header:
                    writer.writerow(["typing_speed", "mouse_moves", "login_hour", "new_device", "location_change", "is_bot"])
                writer.writerow([
                    ml_payload["typing_speed"], 
                    ml_payload["mouse_moves"], 
                    ml_payload["login_hour"], 
                    ml_payload["new_device"], 
                    ml_payload["location_change"],
                    0 # Default to 0 (authentic user)
                ])
        except Exception as e:
            print("Failed to append to training_data.csv:", e)

        ml_response = requests.post(
            "http://127.0.0.1:6000/predict-risk",
            json=ml_payload,
            timeout=3
        )

        if ml_response.status_code == 200:
            ml_json = ml_response.json()
            ml_risk = int(ml_json.get("ml_risk_probability", 0) * 100)
            print("ML Response:", ml_json)
            print("ML Risk Score (%):", ml_risk)

    except Exception as e:
        print("ML service unavailable:", e)

    # -------- TOTAL RISK --------
    total_risk = device_risk + travel_risk + login_time_risk + ml_risk
    print("TOTAL RISK SCORE:", total_risk)
    session["last_risk"] = total_risk

    # -------- FINAL PROFILE --------
    behavior_profile = {
        "userId": session["user"],
        "typing_speed": data.get("typing_speed"),
        "mouse_moves": data.get("mouse_moves"),
        "device": device,
        "location": location,
        "new_device": new_device,
        "device_risk": device_risk,
        "impossible_travel": impossible_travel,
        "travel_risk": travel_risk,
        "login_time_risk": login_time_risk,
        "ml_risk": ml_risk
    }

    print("Behavior Profile:")
    print(behavior_profile)

    # -------- SECURITY DECISION ENGINE --------
    if total_risk >= 70:
        print("ACTION: BLOCK USER")
        session.pop("user", None)
        return jsonify({"status": "blocked", "risk": total_risk})

    elif total_risk >= 40:
        print("ACTION: REQUIRE MFA")
        return jsonify({"status": "mfa_required", "risk": total_risk})

    else:
        print("ACTION: ALLOW")
        return jsonify({"status": "allowed", "risk": total_risk})



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
        print(f"🚨 ACTION: KICKING USER {session['user']} MID-SESSION")
        session.pop("user", None)
        return jsonify({"status": "blocked", "risk": total_risk})

    return jsonify({"status": "allowed", "risk": total_risk})


# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True)
