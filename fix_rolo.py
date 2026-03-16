import sqlite3

conn = sqlite3.connect('C:/Users/sebas/Desktop/cpp/users.db')
cur = conn.cursor()

cur.execute("PRAGMA table_info(users)")
print("Schema:", cur.fetchall())

cur.execute("SELECT * FROM users WHERE username='rolo'")
user = cur.fetchone()
print(f"Rolo Record: {user}")

# If email and password are swapped
if user and "scrypt" in user[2]:
    print("Swapping email and password for rolo...")
    # Update rolo to put email in index 2 and password in index 3
    # Wait, the table schema might be different. Let's just fix rolo's email to be user[3] temporarily or swap them.
    # Actually, email=user[3], password=user[2].
    cur.execute("UPDATE users SET email=?, password=? WHERE username='rolo'", (user[3], user[2]))
    conn.commit()
    print("Fixed rolo in DB.")

conn.close()
