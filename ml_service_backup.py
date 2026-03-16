from flask import Flask, request, jsonify
import numpy as np
from sklearn.linear_model import LogisticRegression

app = Flask(__name__)

# ----------------------------
# TRAIN SIMPLE ML MODEL
# ----------------------------

# Synthetic training data
# [typing_speed (cpm), mouse_moves, login_hour, new_device, location_change]
X_train = np.array([
    [150, 40, 10, 0, 0],  # Normal average typing
    [250, 45, 11, 0, 0],  # Normal fast typing
    [80, 35, 9, 0, 0],    # Normal slow typing
    [350, 60, 14, 0, 0],  # Normal very fast typing 
    [45, 20, 20, 0, 0],   # Normal very slow typing
    [30, 5, 2, 0, 0],     # Normal night-time login
    [1200, 0, 2, 1, 1],   # Bot: pasted text instantly, no movement
    [2000, 0, 3, 1, 1],   # Bot: pasted text instantly
    [1500, 2, 12, 1, 0],  # Bot: pasted text instantly, slight movement
    [0, 0, 1, 1, 1],      # Bot: no typing track at all, 0 movement
    [3000, 0, 4, 1, 0]    # Bot: extremely fast automated login
])

# Labels: 0 = Normal, 1 = Suspicious
y_train = np.array([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1])

model = LogisticRegression()
model.fit(X_train, y_train)

# ----------------------------
# PREDICTION API
# ----------------------------
@app.route("/predict-risk", methods=["POST"])
def predict_risk():
    data = request.get_json()

    features = np.array([[
        data["typing_speed"],
        data["mouse_moves"],
        data["login_hour"],
        data["new_device"],
        data["location_change"]
    ]])

    risk_prob = model.predict_proba(features)[0][1]

    return jsonify({
        "ml_risk_probability": round(float(risk_prob), 2)
    })

if __name__ == "__main__":
    app.run(port=6000)
