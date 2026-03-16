import sqlite3

def migrate():
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        
        # Check if column already exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if "locked_until" not in columns:
            print("Adding locked_until column to users table...")
            cursor.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
            conn.commit()
            print("Migration successful.")
        else:
            print("locked_until column already exists.")
            
        conn.close()
    except Exception as e:
        print(f"Migration failed: {e}")

if __name__ == "__main__":
    migrate()
