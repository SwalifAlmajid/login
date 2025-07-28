import sqlite3

conn = sqlite3.connect('database.db')
cursor = conn.cursor()
cursor.execute("""CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)""")
cursor.execute("INSERT INTO users (username, password) VALUES ('admin', '1234')")
conn.commit()
conn.close()