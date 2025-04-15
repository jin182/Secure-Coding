import sqlite3

# DB 연결
conn = sqlite3.connect('market.db')
cursor = conn.cursor()

# admin 권한 부여 (is_admin=1)
cursor.execute("UPDATE user SET is_admin=1 WHERE username='Lay'")
conn.commit()

# 확인
cursor.execute("SELECT id, username, is_admin FROM user WHERE username='Lay'")
print(cursor.fetchone())

conn.close()