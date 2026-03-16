from flask import Flask, request, jsonify
import numpy as np
from sklearn.linear_model import LogisticRegression

app = Flask(__name__)
@app.route("/")
def home():
    return "ML Security API is running"

import os
import csv
import numpy as np

# ----------------------------
# DYNAMIC ML PROFILING
# ----------------------------

def get_user_history_features(target_username):
    """
    Reads the CSV logs and extracts all typing and mouse data
    specifically for this username where is_bot=0.
    In production, this queries the Time-Series Data Warehouse.
    """
    history = []
    if not os.path.exists("training_data.csv"):
        return history
        
    try:
        with open("training_data.csv", "r") as f:
            reader = csv.DictReader(f)
            # The CSV currently doesn't log username, but we are fixing it retroacitvely 
            # so let's assume the CSV has a 'username' column now, or we just fallback to the whole file
            # for the prototype if username is missing.
            for row in reader:
                # We only want to train on legitimate past behavior
                if row.get("is_bot") == "0":
                    row_user = row.get("username", "testuser")
                    if row_user == target_username:
                        history.append({
                            "typing_speed": float(row["typing_speed"]),
                            "mouse_moves": float(row["mouse_moves"])
                        })
    except Exception as e:
        print("Failed to read history:", e)
        
    return history

def calculate_ml_risk(username, current_speed, current_mouse):
    """
    Calculates behavioral anomaly score. 
    Handles both 'Cold Start' (New Users) and 'Established Users'.
    """
    # 1. GLOBAL HEURISTICS (Applies to everyone)
    if current_speed > 1500:
        return 90 # Instant Bot Flag: Impossible typing speed
    if current_speed > 600 and current_mouse == 0:
        return 80 # High Risk: Pasting text with zero physical movement
    
    # 2. USER BEHAVIORAL PROFILING
    history = get_user_history_features(username)
    num_logins = len(history)
    
    # COLD START: Not enough data to build a personalized baseline yet.
    if num_logins < 5: 
        print(f"User {username} is in Grace Period (Cold Start). Only global rules apply.")
        return 0 # Allow them in to build history
        
    # ESTABLISHED USER: Calculate their specific baseline
    speeds = [h["typing_speed"] for h in history]
    mouses = [h["mouse_moves"] for h in history]
    
    avg_speed = np.mean(speeds)
    std_speed = np.std(speeds) if np.std(speeds) > 0 else 10 # Avoid division by zero
    
    avg_mouse = np.mean(mouses)
    std_mouse = np.std(mouses) if np.std(mouses) > 0 else 5
    
    # Calculate Z-Scores (How many standard deviations away from THEIR normal are they?)
    z_speed = abs(current_speed - avg_speed) / std_speed
    z_mouse = abs(current_mouse - avg_mouse) / std_mouse
    
    # If they are behaving vastly different from their own history (e.g. > 3 std deviations)
    anomaly_score = 0
    if z_speed > 4:
        anomaly_score += 100 # Absolute certainty of anomaly (Hacker speed vs slow baseline)
    elif z_speed > 3:
        anomaly_score += 60 # Very High Risk
    elif z_speed > 2:
        anomaly_score += 30 # Moderate Risk
        
    if z_mouse > 3:
        anomaly_score += 30
        
    print(f"ML Profiling | User: {username} | Avg Speed: {avg_speed:.0f} | Current: {current_speed} | Z-Score: {z_speed:.2f}")
    
    return min(anomaly_score, 100)

import requests
from datetime import datetime
import sqlite3

def get_api_db():
    return sqlite3.connect("api_db.db")

# ----------------------------
# PREDICTION API
# ----------------------------
@app.route("/evaluate", methods=["POST"])
def evaluate():
    # 0. API Key Authentication (Multi-Tenancy)
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"status": "error", "message": "Missing or invalid API Key"}), 401
    
    api_key = auth_header.split(" ")[1]
    
    # Verify API key exists
    with get_api_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT client_name FROM clients WHERE api_key = ?", (api_key,))
        client = cur.fetchone()
        if not client:
             return jsonify({"status": "error", "message": "Invalid API Key"}), 403

    data = request.get_json()
    
    # 1. Extract Raw Telemetry
    user_agent = data.get("user_agent", "").lower()
    ip_address = data.get("ip_address", "")
    username = data.get("username", "unknown")
    typing_speed = data.get("typing_speed", 0)
    mouse_moves = data.get("mouse_moves", 0)
    
    # Fetch Historical context directly from the API Database now instead of the client
    with get_api_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT last_location, last_login_time, last_device
            FROM api_login_context
            WHERE client_api_key = ? AND username = ?
        """, (api_key, username))
        row = cur.fetchone()
        
    last_location = row[0] if row else None
    last_time_str = row[1] if row else None
    last_device = row[2] if row else None
    last_time = datetime.fromisoformat(last_time_str) if last_time_str else None
    
    current_time = datetime.now()
    
    # -------- 2. DEVICE RISK --------
    os_name = "Windows" if "windows" in user_agent else "MacOS" if "mac" in user_agent else "Other"
    browser = "Chrome" if "chrome" in user_agent else "Firefox" if "firefox" in user_agent else "Other"
    current_device = f"{browser}-{os_name}"
    
    new_device = False
    device_risk = 0
    if last_device and last_device != current_device:
        new_device = True
        device_risk = 20
        
    # -------- 3. LOCATION & TRAVEL RISK --------
    current_location = "Unknown"
    if ip_address:
        try:
            # Note: in a production service, you'd use a paid GeoIP database or caching
            res = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=3)
            if res.status_code == 200:
                current_location = res.json().get("country_name", "Unknown")
        except:
            pass

    impossible_travel = False
    travel_risk = 0
    if last_location and last_time:
        diff_minutes = (current_time - last_time).total_seconds() / 60
        if last_location != current_location and diff_minutes < 30:
            impossible_travel = True
            travel_risk = 30
            
    # -------- 4. TIME OF DAY RISK --------
    login_time_risk = 10 if current_time.hour < 6 or current_time.hour > 22 else 0
    
    # -------- 5. ML BEHAVIORAL RISK --------
    # Instead of a global static model, we now use dynamic, personalized behavioral profiling
    ml_risk = calculate_ml_risk(username, typing_speed, mouse_moves)
    
    # -------- 6. CALCULATE TOTAL RISK --------
    total_risk = device_risk + travel_risk + login_time_risk + ml_risk
    
    # Determine Action
    action = "allowed"
    if total_risk >= 70:
        action = "blocked"
    elif total_risk >= 40:
        action = "mfa_required"
        
    # -------- 7. UPDATE CONTEXT IN API DB --------
    # The API is the source of truth for history now
    with get_api_db() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO api_login_context
            (client_api_key, username, last_location, last_login_time, last_device)
            VALUES (?, ?, ?, ?, ?)
        """, (api_key, username, current_location, current_time.isoformat(), current_device))
        conn.commit()
        
    return jsonify({
        "action": action,
        "total_risk": total_risk,
        "location": current_location,
        "breakdown": {
            "device_risk": device_risk,
            "travel_risk": travel_risk,
            "time_risk": login_time_risk,
            "ml_risk": ml_risk
        }
    })

if __name__ == "__main__":
    app.run(port=5000)
