print("===========================================")
print("  MACHINE LEARNING BEHAVIORAL BLOCK DEMO   ")
print("===========================================")
print("Target Account: 'rolo'")
print("Est. Baseline: ~30 CPM (Slow Typist)")
print("Attacker Speed: 250 CPM (Fast Typist)")
print("-------------------------------------------\n")

try:
    import sys
    sys.path.append('.') # Ensure we can import app
    from app import app
    
    app.config['TESTING'] = True
    with app.test_client() as client:
        # 1. Establish session
        with client.session_transaction() as sess:
            sess['user'] = 'rolo'
            
        print("[1] Session Hijacked successfully for target 'rolo'.")

        # 2. Inject Anomaly Telemetry (250 CPM vs 30 CPM baseline).
        print("[2] Dispatching Behavioral Telemetry to Risk Engine...")
        behavior_data = {
            'typing_speed': 250,
            'mouse_moves': 15,
            'user_agent': 'Mozilla/5.0'
        }
        res = client.post('/behavior', json=behavior_data)
        
        print("\n--- RISK ENGINE RESPONSE ---")
        if res.status_code == 200:
            data = res.json
            print(f"Total Risk Calculated: {data.get('risk', 0)} / 100")
            print(f"Final Action Taken:    {data.get('status', 'ERROR').upper()}")
            
            if data.get('status') == 'blocked':
                print("\n✅ SUCCESS: The ML Engine mathematically proved this wasn't Rolo.")
                print("✅ The login was blocked, and the PDF Report is sending NOW!")
            else:
                print("\n❌ FAILED: The Risk Engine did not block the user.")
                
        else:
            print(f"API Error Code: {res.status_code}")

except Exception as e:
    print(f"Simulation Error: {e}")
