import sqlite3

conn = sqlite3.connect('C:/Users/sebas/Desktop/cpp/users.db')
cur = conn.cursor()
cur.execute("SELECT * FROM users WHERE username='rolo'")
user = cur.fetchone()
print(f"Rolo DB Record: {user}")
conn.close()
