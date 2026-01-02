import mysql.connector

# Connect to the database
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="lost2found_db"
)

cursor = conn.cursor()

# Create ai_matches table
create_table_query = """
CREATE TABLE IF NOT EXISTS ai_matches (
    id INT NOT NULL AUTO_INCREMENT,
    lost_item_id INT NOT NULL,
    found_item_id INT NOT NULL,
    similarity_score FLOAT NOT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (lost_item_id) REFERENCES lost_items(id),
    FOREIGN KEY (found_item_id) REFERENCES found_items(id)
);
"""

cursor.execute(create_table_query)
conn.commit()

print("ai_matches table created successfully.")

cursor.close()
conn.close()