console.log("Behavior script running");

let keystrokeTimes = [];
let lastKeyTime = null;

// Typing speed detection
document.addEventListener("keydown", function () {
    let now = Date.now();
    if (lastKeyTime !== null) {
        keystrokeTimes.push(now - lastKeyTime);
    }
    lastKeyTime = now;
});

// Mouse movement detection

let mouseMoves = 0;
document.addEventListener("mousemove", function () 
{
    mouseMoves++;
})

// Send behavior data every 10 seconds
setInterval(function () {
    if (keystrokeTimes.length === 0 && mouseMoves === 0) return;

    let avgTypingSpeed = keystrokeTimes.length > 0
        ? keystrokeTimes.reduce((a, b) => a + b, 0) / keystrokeTimes.length
        : 0;

    let behaviorData = {
        typing_speed: Math.round(avgTypingSpeed),
        mouse_moves: mouseMoves,
        user_agent: navigator.userAgent,
        timestamp: new Date().toISOString()
    };

    fetch("/behavior", {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify(behaviorData)
})
.then(res => res.json())
.then(result => {

    console.log("SECURITY RESPONSE:", result);

    // -------- SECURITY ACTIONS --------

    // BLOCK USER
    if (result.status === "blocked") {
        alert("⚠️ Suspicious activity detected. You have been logged out.");

        window.location.href = "/";
    }

    // MFA REQUIRED
    else if (result.status === "mfa_required") {
        alert("🔐 Additional verification required.");

        window.location.href = "/";
    }

    // ALLOWED
    else if (result.status === "allowed") {
        console.log("User safe. Continue session.");
    }
})
.catch(err => console.log("Security engine error:", err));
    // reset counters
    keystrokeTimes = [];
    mouseMoves = 0;

}, 10000);
