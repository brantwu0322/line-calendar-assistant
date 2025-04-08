import sqlite3
import hashlib
import os

def create_admin(username, password):
    # 如果資料庫不存在，先初始化
    if not os.path.exists('database.db'):
        conn = sqlite3.connect('database.db')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
    else:
        conn = sqlite3.connect('database.db')
    
    # 檢查是否已存在管理員
    cursor = conn.execute('SELECT * FROM admins WHERE username = ?', (username,))
    if cursor.fetchone():
        print(f"管理員 {username} 已存在")
        return
    
    # 建立管理員帳號
    conn.execute(
        'INSERT INTO admins (username, password) VALUES (?, ?)',
        (username, hashlib.sha256(password.encode()).hexdigest())
    )
    conn.commit()
    print(f"成功建立管理員帳號：{username}")

if __name__ == '__main__':
    username = input("請輸入管理員帳號：")
    password = input("請輸入管理員密碼：")
    create_admin(username, password) 