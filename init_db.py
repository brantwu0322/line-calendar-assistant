import os
import sqlite3
import json
import logging
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# 設定日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 資料庫路徑
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'calendar.db')

def init_database():
    """初始化資料庫"""
    try:
        # 確保 instance 目錄存在
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # 創建 users 表
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                line_user_id TEXT PRIMARY KEY,
                google_credentials TEXT,
                google_email TEXT,
                subscription_status TEXT DEFAULT 'free',
                subscription_end_date TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        logger.info("users 表已創建或已存在")
        
        # 創建 events 表
        c.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                line_user_id TEXT,
                event_id TEXT,
                event_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (line_user_id) REFERENCES users (line_user_id)
            )
        ''')
        logger.info("events 表已創建或已存在")
        
        # 創建 admins 表
        c.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        logger.info("admins 表已創建或已存在")
        
        # 檢查默認管理員帳號是否存在
        c.execute("SELECT password FROM admins WHERE username = 'admin'")
        admin = c.fetchone()
        
        if not admin:
            # 如果默認管理員帳號不存在，創建它
            default_username = 'admin'
            default_password = generate_password_hash('admin')
            c.execute('INSERT INTO admins (username, password) VALUES (?, ?)',
                     (default_username, default_password))
            logger.info('已創建默認管理員帳號')
        
        conn.commit()
        conn.close()
        logger.info("資料庫初始化成功")
        
    except Exception as e:
        logger.error(f"資料庫初始化失敗：{str(e)}")
        raise

if __name__ == '__main__':
    init_database() 