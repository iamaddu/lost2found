import mysql.connector

def fix_database():
    try:
        # Connect to your database
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root",  # <--- PUT YOUR PASSWORD HERE
            database="lost2found_db"
        )
        cursor = conn.cursor()

        print("Connected to database...")

        # Run the command to add the missing column
        print("Adding 'finder_email' column...")
        cursor.execute("ALTER TABLE lost_items ADD COLUMN rejection_reason TEXT;")
        
        conn.commit()
        print("✅ Success! The column 'finder_email' has been added.")
        
    except mysql.connector.Error as err:
        # If the error is 1060, it means the column already exists (which is good)
        if err.errno == 1060:
            print("✅ Good news: The column 'finder_email' already exists!")
        else:
            print(f"❌ Error: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

if __name__ == "__main__":
    fix_database()