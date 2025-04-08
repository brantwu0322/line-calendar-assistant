import os
import logging
import sys
import time
from datetime import datetime, timedelta, time as datetime_time
import re
from flask import Flask, request, abort, redirect, url_for, session, render_template, flash, jsonify
from linebot.v3 import WebhookHandler
from linebot.v3.exceptions import InvalidSignatureError
from linebot.v3.webhooks import (
    MessageEvent,
    TextMessageContent,
    AudioMessageContent
)
from linebot.v3.messaging import (
    Configuration,
    ApiClient,
    MessagingApi,
    ReplyMessageRequest,
    TextMessage
)
from linebot.v3.messaging.models import (
    TextMessage as TextSendMessage,
    AudioMessage
)
from linebot.v3.webhooks.models import MessageContent
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow, Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import speech_recognition as sr
import tempfile
import json
import openai
import requests
import traceback
from pydub import AudioSegment
import opencc
import sqlite3
from functools import wraps
import pytz
from dotenv import load_dotenv
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from googleapiclient.errors import HttpError

# 設定日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 載入環境變數
load_dotenv()

# 設定資料庫路徑
DB_PATH = os.path.join(os.getenv('RENDER_DB_PATH', os.path.dirname(os.path.abspath(__file__))), 'users.db')
logger.info(f"Database path: {DB_PATH}")

# 確保資料庫目錄存在
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['WTF_CSRF_ENABLED'] = False
csrf = CSRFProtect(app)
Session(app)

# 初始化 LINE Bot
channel_secret = os.getenv('LINE_CHANNEL_SECRET')
channel_access_token = os.getenv('LINE_CHANNEL_ACCESS_TOKEN')

if not channel_secret or not channel_access_token:
    logger.error('LINE Bot 配置缺失')
    raise ValueError('LINE Bot 配置缺失')

logger.info('Starting Flask application...')
logger.info(f'LINE_CHANNEL_ACCESS_TOKEN: {channel_access_token[:10]}...')
logger.info(f'LINE_CHANNEL_SECRET: {channel_secret[:10]}...')
logger.info(f'GOOGLE_CALENDAR_ID: {os.getenv("GOOGLE_CALENDAR_ID")}')

configuration = Configuration(access_token=channel_access_token)
handler = WebhookHandler(channel_secret)

# Google Calendar API 設定
SCOPES = [
    'https://www.googleapis.com/auth/calendar',
    'https://www.googleapis.com/auth/userinfo.email',
    'openid'  # 新增 openid 範圍
]
API_SERVICE_NAME = 'calendar'
API_VERSION = 'v3'
CLIENT_SECRETS_FILE = 'client_secrets.json'

# 初始化簡體轉繁體轉換器
converter = opencc.OpenCC('s2twp')

def with_db_connection(func):
    """資料庫連接裝飾器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            return func(conn, *args, **kwargs)
        except Exception as e:
            logger.error(f'資料庫操作錯誤: {str(e)}')
            logger.error(f'詳細錯誤資訊：\n{traceback.format_exc()}')
            raise
        finally:
            if conn:
                conn.close()
    return wrapper

def with_error_handling(func):
    """錯誤處理裝飾器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f'執行 {func.__name__} 時發生錯誤: {str(e)}')
            logger.error(f'詳細錯誤資訊：\n{traceback.format_exc()}')
            raise
    return wrapper

def send_line_message(reply_token, text):
    """發送 LINE 訊息"""
    try:
        if not text:
            logger.error('嘗試發送空訊息')
            return
            
        with ApiClient(configuration) as api_client:
            messaging_api = MessagingApi(api_client)
            messaging_api.reply_message(
                ReplyMessageRequest(
                    reply_token=reply_token,
                    messages=[TextMessage(text=text)]
                )
            )
    except Exception as e:
        logger.error(f'發送訊息時發生錯誤: {str(e)}')
        raise

def parse_datetime_and_summary(text):
    """解析文字訊息中的日期時間和摘要"""
    try:
        # 使用 OpenAI API 解析文字
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": """你是一個專業的日期時間解析助手。請從文字中提取日期時間和事件摘要。
                    規則：
                    1. 如果提到"週X"或"星期X"，請計算最近的那個日期
                    2. 如果沒有明確說明是上午還是下午，3-11點預設為上午，12-2點預設為下午
                    3. 輸出格式必須是 JSON：{"date": "2024-04-06", "time": "15:00", "summary": "事件摘要"}
                    
                    範例：
                    輸入："週五下午三點開會"
                    輸出：{"date": "2024-04-12", "time": "15:00", "summary": "開會"}
                    """
                },
                {"role": "user", "content": text}
            ]
        )
        
        # 解析回應
        result = response.choices[0].message.content
        logger.info(f"OpenAI 解析結果: {result}")
        
        try:
            # 解析 JSON
            data = json.loads(result)
            if 'date' in data and 'time' in data and 'summary' in data:
                # 組合日期和時間
                datetime_str = f"{data['date']} {data['time']}"
                parsed_datetime = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M')
                return parsed_datetime, data['summary'], False
        except json.JSONDecodeError:
            logger.error("無法解析 JSON 回應")
        except ValueError as e:
            logger.error(f"日期時間格式錯誤: {str(e)}")
        
        return None, None, False
    except Exception as e:
        logger.error(f"解析日期時間時發生錯誤: {str(e)}")
        return None, None, False

def require_authorization(func):
    """檢查使用者是否已授權的裝飾器"""
    @wraps(func)
    def wrapper(event, *args, **kwargs):
        line_user_id = event.source.user_id
        
        # 檢查使用者訂閱狀態
        user_status = get_user_status(line_user_id)
        if not user_status or user_status['status'] == 'free':
            # 如果使用者未訂閱，提供訂閱連結
            subscribe_url = url_for('subscribe', line_user_id=line_user_id, _external=True)
            messaging_api.reply_message_with_http_info(
                ReplyMessageRequest(
                    reply_token=event.reply_token,
                    messages=[TextMessage(text=f"請先完成訂閱以使用完整功能：\n{subscribe_url}")]
                )
            )
            return
        
        # 檢查 Google Calendar 授權
        service, error = get_google_calendar_service()
        if error:
            auth_url = url_for('authorize', line_user_id=line_user_id, _external=True)
            messaging_api.reply_message_with_http_info(
                ReplyMessageRequest(
                    reply_token=event.reply_token,
                    messages=[TextMessage(text=f"請先完成 Google Calendar 授權：\n{auth_url}")]
                )
            )
            return
        
        return func(event, service, *args, **kwargs)
    return wrapper

@with_db_connection
def init_db(conn):
    """初始化資料庫"""
    c = conn.cursor()
    
    # 創建用戶表
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        line_user_id TEXT UNIQUE NOT NULL,
        google_credentials TEXT,
        google_email TEXT,
        subscription_status TEXT DEFAULT 'free',
        subscription_end_date TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # 創建行程記錄表
    c.execute('''
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        line_user_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        summary TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (line_user_id) REFERENCES users (line_user_id)
    )
    ''')
    
    # 創建管理員表
    c.execute('''
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # 創建訂單表
    c.execute('''
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id TEXT UNIQUE NOT NULL,
        line_user_id TEXT NOT NULL,
        amount INTEGER NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (line_user_id) REFERENCES users (line_user_id)
    )
    ''')
    
    # 檢查是否已存在管理員帳號
    c.execute('SELECT COUNT(*) FROM admins')
    if c.fetchone()[0] == 0:
        # 創建默認管理員帳號
        default_username = 'admin'
        default_password = generate_password_hash('admin')
        c.execute('INSERT INTO admins (username, password) VALUES (?, ?)',
                 (default_username, default_password))
        logger.info('已創建默認管理員帳號')
    
    conn.commit()
    logger.info('資料庫初始化完成')

@with_db_connection
def get_user_status(conn, line_user_id):
    """獲取使用者狀態"""
    c = conn.cursor()
    c.execute('''SELECT subscription_status, subscription_end_date 
                 FROM users WHERE line_user_id = ?''', (line_user_id,))
    result = c.fetchone()
    
    if result:
        return {
            'status': result[0],
            'end_date': result[1]
        }
    return None

@with_db_connection
def update_user_subscription(conn, line_user_id, status, end_date):
    """更新使用者訂閱狀態"""
    c = conn.cursor()
    c.execute('''UPDATE users 
                 SET subscription_status = ?, subscription_end_date = ?
                 WHERE line_user_id = ?''', (status, end_date, line_user_id))
    conn.commit()
    logger.info(f"Updated subscription for user: {line_user_id}")
    return True

@with_db_connection
def create_order(conn, line_user_id, amount):
    """建立訂單"""
    order_id = f"ORDER_{int(time.time())}_{line_user_id[:8]}"
    c = conn.cursor()
    c.execute('''INSERT INTO orders (order_id, line_user_id, amount, status)
                 VALUES (?, ?, ?, ?)''', (order_id, line_user_id, amount, 'pending'))
    conn.commit()
    return order_id

@with_db_connection
def verify_admin(conn, username, password):
    """驗證管理員帳號密碼"""
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM admins WHERE username = ?', (username,))
    result = cursor.fetchone()
    
    if result is None:
        return False
    
    stored_password = result[0]
    return check_password_hash(stored_password, password)

@with_db_connection
def get_all_users(conn, search_term=None):
    """獲取所有已授權的使用者，支援搜尋"""
    c = conn.cursor()
    if search_term:
        # 搜尋 LINE ID 或 Google 帳號
        c.execute('''
            SELECT line_user_id, google_email, subscription_status, subscription_end_date 
            FROM users 
            WHERE line_user_id LIKE ? OR google_email LIKE ?
        ''', (f'%{search_term}%', f'%{search_term}%'))
    else:
        c.execute('SELECT line_user_id, google_email, subscription_status, subscription_end_date FROM users')
    
    users = []
    for row in c.fetchall():
        users.append({
            'line_user_id': row[0],
            'google_email': row[1],
            'subscription_status': row[2],
            'subscription_end_date': row[3]
        })
    return users

@with_db_connection
def get_user_credentials(conn, line_user_id):
    """獲取用戶認證"""
    c = conn.cursor()
    c.execute('SELECT google_credentials FROM users WHERE line_user_id = ?', (line_user_id,))
    result = c.fetchone()
    
    if result and result[0]:
        try:
            creds_dict = json.loads(result[0])
            return creds_dict
        except json.JSONDecodeError:
            logger.error(f"無法解析用戶 {line_user_id} 的憑證 JSON")
            return None
    return None

def get_db_connection():
    """獲取資料庫連接"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        logger.error(f"連接資料庫時發生錯誤: {str(e)}")
        raise

@with_db_connection
def save_user_credentials(conn, line_user_id, credentials):
    """保存用戶認證"""
    try:
        cursor = conn.cursor()
        
        # 將憑證轉換為字典格式
        creds_dict = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        
        # 檢查用戶是否已存在
        cursor.execute('SELECT line_user_id FROM users WHERE line_user_id = ?', (line_user_id,))
        user_exists = cursor.fetchone() is not None
        
        if user_exists:
            # 如果用戶已存在，只更新 google_credentials
            cursor.execute('UPDATE users SET google_credentials = ? WHERE line_user_id = ?',
                         (json.dumps(creds_dict), line_user_id))
        else:
            # 如果用戶不存在，創建新用戶
            cursor.execute('''
            INSERT INTO users (line_user_id, google_credentials, subscription_status, subscription_end_date)
            VALUES (?, ?, 'free', NULL)
            ''', (line_user_id, json.dumps(creds_dict)))
        
        conn.commit()
        logger.info(f"已儲存用戶 {line_user_id} 的憑證")
        return True
    except Exception as e:
        logger.error(f"儲存用戶憑證時發生錯誤: {str(e)}")
        raise

def get_google_calendar_service(line_user_id=None):
    """取得使用者的 Google Calendar 服務"""
    try:
        if not line_user_id:
            return None, "未提供用戶 ID"

        # 嘗試獲取用戶的憑證
        creds_dict = get_user_credentials(line_user_id)
        if not creds_dict:
            # 如果沒有憑證，返回授權 URL
            credentials_json = os.getenv('GOOGLE_CREDENTIALS')
            if not credentials_json:
                return None, "未設定 GOOGLE_CREDENTIALS 環境變數"
            
            try:
                credentials_info = json.loads(credentials_json)
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                    json.dump(credentials_info, temp_file)
                    temp_file_path = temp_file.name
                
                # 確保使用 HTTPS
                app_url = os.getenv('APP_URL', 'https://line-calendar-assistant.onrender.com').rstrip('/')
                if not app_url.startswith('https://'):
                    app_url = f"https://{app_url.replace('http://', '')}"
                redirect_uri = f"{app_url}/oauth2callback"
                
                logger.info(f"使用重定向 URI: {redirect_uri}")
                
                # 設定 OAuth 2.0 流程
                flow = Flow.from_client_secrets_file(
                    temp_file_path,
                    SCOPES,
                    redirect_uri=redirect_uri
                )
                os.unlink(temp_file_path)
                
                # 生成授權 URL
                authorization_url, _ = flow.authorization_url(
                    access_type='offline',
                    include_granted_scopes='true',
                    state=line_user_id
                )
                
                logger.info(f"生成授權 URL: {authorization_url}")
                return None, authorization_url
                
            except json.JSONDecodeError:
                return None, "GOOGLE_CREDENTIALS 環境變數格式錯誤"
            except Exception as e:
                logger.error(f"初始化 Google Calendar 流程時發生錯誤：{str(e)}")
                return None, f"無法初始化 Google Calendar 授權流程：{str(e)}"
        
        try:
            # 使用憑證字典創建 Credentials 對象
            credentials = Credentials(
                token=creds_dict['token'],
                refresh_token=creds_dict['refresh_token'],
                token_uri=creds_dict['token_uri'],
                client_id=creds_dict['client_id'],
                client_secret=creds_dict['client_secret'],
                scopes=creds_dict['scopes']
            )
            
            # 如果憑證過期，嘗試刷新
            if credentials.expired and credentials.refresh_token:
                try:
                    credentials.refresh(Request())
                    # 更新資料庫中的憑證
                    save_user_credentials(line_user_id, credentials)
                    logger.info(f"已刷新用戶 {line_user_id} 的憑證")
                except Exception as e:
                    logger.error(f"刷新憑證時發生錯誤：{str(e)}")
                    # 如果刷新失敗，返回授權 URL
                    return None, "憑證已過期，需要重新授權"
            
            # 建立服務
            service = build('calendar', 'v3', credentials=credentials)
            return service, None
            
        except Exception as e:
            logger.error(f"取得 Google Calendar 服務時發生錯誤：{str(e)}")
            return None, "Google Calendar 服務發生錯誤"
    except Exception as e:
        logger.error(f"Google Calendar 服務發生未預期錯誤：{str(e)}")
        return None, f"系統錯誤：{str(e)}"

# OpenAI API 設定
openai.api_key = os.getenv('OPENAI_API_KEY')

# Google Calendar API 設定
SCOPES = [
    'https://www.googleapis.com/auth/calendar',
    'https://www.googleapis.com/auth/userinfo.email',
    'openid'  # 新增 openid 範圍
]

@with_error_handling
def parse_event_text(text):
    """解析文字中的行程資訊"""
    logger.info(f"開始解析文字：{text}")
    
    try:
        # 使用 GPT-4 進行語意分析
        logger.info("正在調用 GPT-4 API...")
        
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {
                    "role": "system",
                    "content": """你是一個行程解析助手。請將用戶的自然語言輸入轉換成結構化的時間資訊。
                    輸出格式要求：
                    {
                        "date_type": "今天|明天|後天|大後天|下週一|下週二|下週三|下週四|下週五|下週六|下週日|下下週一|下下週二|下下週三|下下週四|下下週五|下下週六|下下週日|連續X個週Y",
                        "time_period": "上午|下午",
                        "hour": "小時數字",
                        "minute": "分鐘數字",
                        "duration_minutes": "行程持續時間（分鐘）",
                        "is_recurring": false,
                        "recurrence_count": null,
                        "summary": "事件描述"
                    }
                    
                    規則：
                    1. 時間解析：
                       - "早上"、"上午"、"早上"、"早上" 都視為 "上午"
                       - "下午"、"下午"、"晚上"、"晚上" 都視為 "下午"
                       - 如果沒有指定上午/下午，根據小時判斷（12點前為上午，12點後為下午）
                       - 數字可以用中文或阿拉伯數字表示，都要轉換成阿拉伯數字
                       - "點"、"時" 都表示小時
                       - "分" 表示分鐘
                       - "半" 表示 30 分
                       - 如果沒有指定持續時間，預設為 60 分鐘
                       - 持續時間可以用"分鐘"、"小時"、"半小時"等表示
                    
                    2. 日期解析：
                       - "今天" 指今天
                       - "明天" 指明天
                       - "後天" 指後天
                       - "大後天" 指大後天
                       - "下週X" 指下週的某一天（例如：今天是週一，說"下週三"就是指下週三）
                       - "下下週X" 指下下週的某一天（例如：今天是週一，說"下下週三"就是指下下週三）
                       - "連續X個週Y" 指連續X週的週Y
                       - "X天後" 指X天後
                    
                    3. 循環事件：
                       - 只有明確包含「每週」、「每個禮拜」或「連續X個週Y」等循環描述時才設為 true
                       - recurrence_count 只有在 is_recurring 為 true 時才設定數值
                    
                    4. 事件描述：
                       - 保留原始描述中的關鍵資訊
                       - 移除時間相關的描述詞
                    
                    範例：
                    1. 輸入：「明天下午兩點開會預計30分鐘」
                       輸出：{
                           "date_type": "明天",
                           "time_period": "下午",
                           "hour": "2",
                           "minute": "0",
                           "duration_minutes": "30",
                           "is_recurring": false,
                           "recurrence_count": null,
                           "summary": "開會"
                       }
                    
                    2. 輸入：「下週三早上九點去看牙醫預計一小時」
                       輸出：{
                           "date_type": "下週三",
                           "time_period": "上午",
                           "hour": "9",
                           "minute": "0",
                           "duration_minutes": "60",
                           "is_recurring": false,
                           "recurrence_count": null,
                           "summary": "去看牙醫"
                       }
                    
                    3. 輸入：「每週五下午三點做瑜珈預計一個半小時」
                       輸出：{
                           "date_type": "下週五",
                           "time_period": "下午",
                           "hour": "3",
                           "minute": "0",
                           "duration_minutes": "90",
                           "is_recurring": true,
                           "recurrence_count": 1,
                           "summary": "做瑜珈"
                       }
                    
                    只輸出 JSON 格式，不要有其他文字。如果無法解析，輸出空物件 {}.
                    """
                },
                {
                    "role": "user",
                    "content": text
                }
            ],
            temperature=0
        )
        
        logger.info("收到 GPT-4 回應")
        logger.info(f"GPT-4 原始回應：{response.choices[0].message.content}")
        
        parsed_data = json.loads(response.choices[0].message.content)
        logger.info(f"GPT 解析結果：{json.dumps(parsed_data, ensure_ascii=False)}")
        
        if not parsed_data:
            logger.info("GPT 無法解析文字")
            return None
            
        # 取得當前時間
        now = datetime.now()
        today = now.date()
        logger.info(f"當前日期：{today}")
        
        # 解析日期
        date_str = parsed_data.get('date_type')
        if not date_str:
            logger.info("未找到日期類型")
            return None
            
        logger.info(f"解析到的日期類型：{date_str}")
        
        # 計算目標日期
        if date_str == '今天':
            target_date = today
        elif date_str == '明天':
            target_date = today + timedelta(days=1)
        elif date_str == '後天':
            target_date = today + timedelta(days=2)
        elif date_str == '大後天':
            target_date = today + timedelta(days=3)
        elif date_str.startswith('下週'):
            weekday_map = {'一': 0, '二': 1, '三': 2, '四': 3, '五': 4, '六': 5, '日': 6}
            target_weekday = weekday_map[date_str[2]]
            current_weekday = today.weekday()
            
            # 計算到下週目標日期的天數
            days_ahead = (target_weekday - current_weekday) % 7
            if days_ahead <= 0:
                days_ahead += 7  # 如果目標日期在本週或之前，加7天到下週
            
            # 計算目標日期
            target_date = today + timedelta(days=days_ahead)
            
            logger.info(f"計算下週日期：今天是週{current_weekday + 1}，目標是週{target_weekday + 1}，需要 {days_ahead} 天")
        elif date_str.startswith('下下週'):
            weekday_map = {'一': 0, '二': 1, '三': 2, '四': 3, '五': 4, '六': 5, '日': 6}
            target_weekday = weekday_map[date_str[3]]
            current_weekday = today.weekday()
            
            # 先找到下一個目標週幾
            days_until_next = (target_weekday - current_weekday) % 7
            if days_until_next == 0:
                days_until_next = 7
            
            # 計算到下下週的天數
            days_to_next_next_week = 14 - current_weekday
            
            # 確保是下下週的日期
            target_date = today + timedelta(days=days_to_next_next_week + target_weekday)
            
            logger.info(f"計算下下週日期：今天是週{current_weekday + 1}，目標是週{target_weekday + 1}，到下下週需要{days_to_next_next_week}天")
        elif date_str.startswith('連續'):
            # 解析連續週數
            count = int(date_str.split('個')[0].replace('連續', ''))
            weekday_str = date_str.split('週')[1]
            weekday_map = {'一': 0, '二': 1, '三': 2, '四': 3, '五': 4, '六': 5, '日': 6}
            target_weekday = weekday_map[weekday_str]
            current_weekday = today.weekday()
            # 修改：確保是下週的日期
            days_ahead = target_weekday - current_weekday
            if days_ahead <= 0:  # 如果目標日期在本週或之前，則加7天到下週
                days_ahead += 7
            target_date = today + timedelta(days=days_ahead)
            parsed_data['recurrence_count'] = count
            logger.info(f"計算連續事件日期：今天是週{current_weekday + 1}，目標是週{target_weekday + 1}，相差{days_ahead}天")
        elif date_str.endswith('天後'):
            # 解析 X 天後
            days = int(date_str.replace('天後', ''))
            target_date = today + timedelta(days=days)
        else:
            logger.info(f"無法解析的日期格式：{date_str}")
            return None
        
        logger.info(f"計算得到的目標日期：{target_date}")
        
        # 設定時間
        hour = int(parsed_data.get('hour', 0))
        minute = int(parsed_data.get('minute', 0))
        time_period = parsed_data.get('time_period')
        
        logger.info(f"解析到的時間：{hour}點{minute}分 {time_period}")
        
        # 處理上午/下午
        if time_period == '下午' and hour < 12:
            hour += 12
        elif time_period == '上午' and hour == 12:
            hour = 0
        
        logger.info(f"轉換後的時間：{hour}點{minute}分")
        
        # 設定持續時間（預設為 60 分鐘）
        duration_minutes = int(parsed_data.get('duration_minutes', 60))
        
        start_time = datetime.combine(target_date, datetime_time(hour, minute))
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        logger.info(f"開始時間：{start_time}")
        logger.info(f"結束時間：{end_time}")
        
        # 建立事件資料
        event_data = {
            'summary': parsed_data.get('summary', text),
            'start': {
                'dateTime': start_time.isoformat(),
                'timeZone': 'Asia/Taipei',
            },
            'end': {
                'dateTime': end_time.isoformat(),
                'timeZone': 'Asia/Taipei',
            },
        }
        
        # 只有在明確指定循環事件時才添加重複規則
        is_recurring = parsed_data.get('is_recurring', False)
        recurrence_count = parsed_data.get('recurrence_count')
        
        if is_recurring and recurrence_count:
            event_data['recurrence'] = [
                f'RRULE:FREQ=WEEKLY;COUNT={recurrence_count}'
            ]
            logger.info(f"設定循環事件：每週重複 {recurrence_count} 次")
        
        logger.info(f"最終解析結果：{json.dumps(event_data, ensure_ascii=False)}")
        return event_data
    except Exception as e:
        logger.error(f"解析文字時發生錯誤: {str(e)}")
        logger.exception("詳細錯誤資訊：")
        return None

@with_error_handling
def parse_date_query(text):
    """解析日期查詢請求"""
    logger.info(f"開始解析日期查詢：{text}")
    
    try:
        # 使用 GPT-4 進行語意分析
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {
                    "role": "system",
                    "content": """你是一個日期解析助手。請將用戶的自然語言輸入轉換成結構化的日期資訊。
                    輸出格式要求：
                    {
                        "date_type": "今天|明天|後天|大後天|下週一|下週二|下週三|下週四|下週五|下週六|下週日|下下週一|下下週二|下下週三|下下週四|下下週五|下下週六|下下週日|X月Y日|X/Y|default|週一|週二|週三|週四|週五|週六|週日",
                        "is_date_range": false,
                        "start_date": null,
                        "end_date": null
                    }
                    
                    規則：
                    1. 如果用戶輸入「查詢行程」，將 date_type 設為 "default"
                    2. 如果用戶輸入「查詢 X/Y 的行程」或「X/Y 的行程」，將 date_type 設為 "X/Y"
                    3. 如果用戶輸入「查詢週X的行程」或「週X的行程」，將 date_type 設為 "週X"
                    4. 如果用戶輸入「查詢下週X的行程」或「下週X的行程」，將 date_type 設為 "下週X"
                    5. 如果用戶輸入「查詢 X月Y日 的行程」或「X月Y日的行程」，將 date_type 設為 "X月Y日"
                    
                    範例：
                    1. 輸入：「查詢行程」
                       輸出：{
                           "date_type": "default",
                           "is_date_range": false,
                           "start_date": null,
                           "end_date": null
                       }
                    
                    2. 輸入：「查詢 4/9 的行程」或「4/9 的行程」
                       輸出：{
                           "date_type": "4/9",
                           "is_date_range": false,
                           "start_date": null,
                           "end_date": null
                       }
                    
                    3. 輸入：「查詢週五的行程」或「週五的行程」
                       輸出：{
                           "date_type": "週五",
                           "is_date_range": false,
                           "start_date": null,
                           "end_date": null
                       }
                    
                    4. 輸入：「查詢下週三的行程」或「下週三的行程」
                       輸出：{
                           "date_type": "下週三",
                           "is_date_range": false,
                           "start_date": null,
                           "end_date": null
                       }
                    
                    只輸出 JSON 格式，不要有其他文字。如果無法解析，輸出空物件 {}。
                    """
                },
                {"role": "user", "content": text}
            ],
            temperature=0
        )
        
        logger.info("收到 GPT-4 回應")
        logger.info(f"GPT-4 原始回應：{response.choices[0].message.content}")
        
        parsed_data = json.loads(response.choices[0].message.content)
        logger.info(f"GPT 解析結果：{json.dumps(parsed_data, ensure_ascii=False)}")
        
        if not parsed_data:
            logger.info("GPT 無法解析文字")
            return None
            
        # 取得當前時間
        now = datetime.now()
        today = now.date()
        logger.info(f"當前日期：{today}")
        
        # 如果是預設查詢（未來7天）
        if parsed_data.get('date_type') == 'default':
            start_date = today
            end_date = today + timedelta(days=7)
            return start_date, end_date, True
            
        # 解析日期
        if parsed_data.get('is_date_range'):
            # 處理日期範圍
            start_date = datetime.strptime(parsed_data['start_date'], '%Y-%m-%d').date()
            end_date = datetime.strptime(parsed_data['end_date'], '%Y-%m-%d').date()
            return start_date, end_date, True
        else:
            # 處理單一日期
            date_str = parsed_data.get('date_type')
            if not date_str:
                logger.info("未找到日期類型")
                return None
                
            logger.info(f"解析到的日期類型：{date_str}")
            
            # 計算目標日期
            if date_str == '今天':
                target_date = today
            elif date_str == '明天':
                target_date = today + timedelta(days=1)
            elif date_str == '後天':
                target_date = today + timedelta(days=2)
            elif date_str == '大後天':
                target_date = today + timedelta(days=3)
            elif date_str.startswith('下週'):
                weekday_map = {'一': 0, '二': 1, '三': 2, '四': 3, '五': 4, '六': 5, '日': 6}
                target_weekday = weekday_map[date_str[2]]
                current_weekday = today.weekday()
                
                # 計算到下週目標日期的天數
                days_ahead = (target_weekday - current_weekday) % 7
                days_ahead += 7  # 確保是下週
                
                # 計算目標日期
                target_date = today + timedelta(days=days_ahead)
                
                logger.info(f"計算下週日期：今天是週{current_weekday + 1}，目標是週{target_weekday + 1}，需要 {days_ahead} 天")
                return target_date, target_date, False
            elif date_str.startswith('下下週'):
                weekday_map = {'一': 0, '二': 1, '三': 2, '四': 3, '五': 4, '六': 5, '日': 6}
                target_weekday = weekday_map[date_str[3]]
                current_weekday = today.weekday()
                
                # 先找到下一個目標週幾
                days_until_next = (target_weekday - current_weekday) % 7
                if days_until_next == 0:
                    days_until_next = 7
                
                # 計算到下下週的天數
                days_to_next_next_week = 14 - current_weekday
                
                # 確保是下下週的日期
                target_date = today + timedelta(days=days_to_next_next_week + target_weekday)
                
                logger.info(f"計算下下週日期：今天是週{current_weekday + 1}，目標是週{target_weekday + 1}，到下下週需要{days_to_next_next_week}天")
            elif '月' in date_str and '日' in date_str:
                # 處理 X月Y日 格式的日期
                month = int(date_str.split('月')[0])
                day = int(date_str.split('月')[1].split('日')[0])
                target_date = today.replace(month=month, day=day)
                if target_date < today:
                    target_date = target_date.replace(year=target_date.year + 1)
            elif '/' in date_str:
                # 處理 X/Y 格式的日期
                month, day = map(int, date_str.split('/'))
                target_date = today.replace(month=month, day=day)
                if target_date < today:
                    target_date = target_date.replace(year=target_date.year + 1)
            elif date_str.startswith('週'):
                weekday_map = {'一': 0, '二': 1, '三': 2, '四': 3, '五': 4, '六': 5, '日': 6}
                target_weekday = weekday_map[date_str[1]]
                current_weekday = today.weekday()
                
                # 計算到目標日期的天數
                days_ahead = (target_weekday - current_weekday) % 7
                if days_ahead == 0:
                    days_ahead = 7  # 如果是今天，顯示下週的日期
                
                # 計算目標日期
                target_date = today + timedelta(days=days_ahead)
                
                logger.info(f"計算週X日期：今天是週{current_weekday + 1}，目標是週{target_weekday + 1}，需要 {days_ahead} 天")
            elif date_str.startswith('下週'):
                weekday_map = {'一': 0, '二': 1, '三': 2, '四': 3, '五': 4, '六': 5, '日': 6}
                target_weekday = weekday_map[date_str[2]]
                current_weekday = today.weekday()
                
                # 計算到下週目標日期的天數
                days_ahead = (target_weekday - current_weekday) % 7
                days_ahead += 7  # 確保是下週
                
                # 計算目標日期
                target_date = today + timedelta(days=days_ahead)
                
                logger.info(f"計算下週日期：今天是週{current_weekday + 1}，目標是週{target_weekday + 1}，需要 {days_ahead} 天")
            else:
                logger.info(f"無法解析的日期格式：{date_str}")
                return None
            
            logger.info(f"計算得到的目標日期：{target_date}")
            return target_date, target_date, False
            
    except Exception as e:
        logger.error(f"解析日期查詢時發生錯誤: {str(e)}")
        logger.exception("詳細錯誤資訊：")
        return None

@with_error_handling
def create_calendar_event(service, event_data, line_user_id):
    """建立 Google Calendar 事件"""
    try:
        logger.info("開始建立 Google Calendar 事件")
        logger.info(f"事件資料：{json.dumps(event_data, ensure_ascii=False)}")
        
        logger.info("準備建立事件")
        # 使用 'primary' 代表使用者的主要日曆
        result = service.events().insert(calendarId='primary', body=event_data).execute()
        logger.info(f"成功建立事件: {result.get('htmlLink')}")
        
        # 儲存事件到資料庫
        save_event(line_user_id, result['id'], event_data['summary'],
                 event_data['start']['dateTime'],
                 event_data['end']['dateTime'])
        
        # 回覆用戶
        start_time = datetime.fromisoformat(event_data['start']['dateTime'].replace('Z', '+00:00'))
        end_time = datetime.fromisoformat(event_data['end']['dateTime'].replace('Z', '+00:00'))
        formatted_start = start_time.strftime('%Y年%m月%d日 %H:%M')
        formatted_end = end_time.strftime('%H:%M')
        
        reply_text = f"✅ 已成功建立行程：\n\n"
        reply_text += f"📅 時間：{formatted_start} - {formatted_end}\n"
        reply_text += f"📝 內容：{event_data['summary']}\n\n"
        reply_text += f"🔗 查看行程：{result.get('htmlLink')}"
        
        return True, reply_text
    except Exception as e:
        logger.error(f"建立事件時發生錯誤: {str(e)}")
        logger.exception("詳細錯誤資訊：")
        return False, str(e)

@app.route('/callback', methods=['POST'])
@with_error_handling
def callback():
    """處理 LINE Bot 的回調請求"""
    signature = request.headers['X-Line-Signature']
    body = request.get_data(as_text=True)
    
    try:
        handler.handle(body, signature)
        return 'OK'
    except InvalidSignatureError:
        logger.error('無效的簽名')
        abort(400)
    except Exception as e:
        logger.error(f'處理回調時發生錯誤: {str(e)}')
        abort(500)

@handler.add(MessageEvent, message=TextMessageContent)
def handle_message(event):
    """處理文字訊息"""
    try:
        text = event.message.text
        user_id = event.source.user_id
        reply_token = event.reply_token
        logger.info(f'收到文字訊息: {text}')
        
        # 檢查用戶是否已授權
        service, error = get_google_calendar_service(user_id)
        if error and isinstance(error, str) and 'accounts.google.com' in error:
            # 如果是授權 URL，提供更友善的提示
            auth_message = (
                "您好！為了幫您管理行程，我需要先取得您的 Google Calendar 授權喔 😊\n\n"
                "請按照以下步驟進行授權：\n"
                "1. 複製下方連結\n"
                "2. 使用手機瀏覽器（Safari 或 Chrome）開啟\n"
                "3. 登入您的 Google 帳號並同意授權\n\n"
                f"{error}\n\n"
                "完成授權後，請再次傳送您的指令給我 🙂"
            )
            send_line_message(reply_token, auth_message)
            return
        elif error:
            send_line_message(reply_token, f"抱歉，發生了一點問題：{error}\n請稍後再試，或聯繫系統管理員協助 🙏")
            return
            
        # 查詢行程
        if any(keyword in text for keyword in ['查詢行程', '查看行程', '我的行程']) or '的行程' in text:
            try:
                # 解析日期查詢
                logger.info(f"開始解析日期查詢：{text}")
                date_query = parse_date_query(text)
                if date_query:
                    start_date, end_date, is_range = date_query
                    
                    # 設定時間範圍
                    start_time = datetime.combine(start_date, datetime_time.min).isoformat() + 'Z'
                    end_time = datetime.combine(end_date, datetime_time.max).isoformat() + 'Z'
                    
                    # 查詢行程
                    events_result = service.events().list(
                        calendarId='primary',
                        timeMin=start_time,
                        timeMax=end_time,
                        singleEvents=True,
                        orderBy='startTime'
                    ).execute()
                    events = events_result.get('items', [])
                    
                    if not events:
                        if is_range:
                            send_line_message(reply_token, f"{start_date.strftime('%Y年%m月%d日')} 到 {end_date.strftime('%Y年%m月%d日')} 沒有行程安排。")
                        else:
                            send_line_message(reply_token, f"{start_date.strftime('%Y年%m月%d日')} 沒有行程安排。")
                        return
                    
                    # 格式化行程訊息
                    if is_range:
                        message = f'📅 {start_date.strftime("%Y年%m月%d日")} 到 {end_date.strftime("%Y年%m月%d日")} 的行程：\n\n'
                    else:
                        message = f'📅 {start_date.strftime("%Y年%m月%d日")} 的行程：\n\n'
                        
                    for i, event in enumerate(events, 1):
                        start = event['start'].get('dateTime', event['start'].get('date'))
                        end = event['end'].get('dateTime', event['end'].get('date'))
                        
                        # 轉換時間格式
                        start_time = datetime.fromisoformat(start.replace('Z', '+00:00'))
                        end_time = datetime.fromisoformat(end.replace('Z', '+00:00'))
                        
                        # 格式化時間
                        if 'T' in start:  # 有具體時間的行程
                            time_str = f"{start_time.strftime('%H:%M')} - {end_time.strftime('%H:%M')}"
                        else:  # 全天行程
                            time_str = "全天"
                        
                        message += f"{i}. ⏰ {time_str}\n"
                        message += f"   📝 {event['summary']}\n"
                        if event.get('description'):
                            message += f"   📋 {event['description']}\n"
                        message += "\n"
                    
                    message += "\n💡 提示：\n"
                    message += "使用「修改行程 [編號] [新時間]」來修改行程\n"
                    message += "使用「刪除行程 [編號]」來刪除行程"
                    
                    # 如果訊息太長，分多次發送
                    if len(message) > 5000:
                        chunks = [message[i:i+5000] for i in range(0, len(message), 5000)]
                        for chunk in chunks:
                            send_line_message(reply_token, chunk)
            except Exception as e:
                logger.error(f"查詢行程時發生錯誤: {str(e)}")
                send_line_message(reply_token, "查詢行程時發生錯誤，請稍後再試。")

    except Exception as e:
        logger.error(f"處理文字訊息時發生錯誤: {str(e)}")
        send_line_message(reply_token, "處理文字訊息時發生錯誤，請稍後再試。")

def handle_event_creation(service, text):
    """處理新增行程"""
    try:
        # 解析日期時間和摘要
        event_datetime, summary, is_all_day = parse_datetime_and_summary(text)
        if not event_datetime or not summary:
            return "無法理解時間或內容，請使用類似「明天下午三點開會」的格式"
        
        # 設定結束時間（預設一小時）
        end_datetime = event_datetime + timedelta(hours=1)
        
        # 建立行程
        event = {
            'summary': summary,
            'start': {
                'dateTime': event_datetime.isoformat(),
                'timeZone': 'Asia/Taipei',
            },
            'end': {
                'dateTime': end_datetime.isoformat(),
                'timeZone': 'Asia/Taipei',
            },
        }
        
        event = service.events().insert(calendarId='primary', body=event).execute()
        
        # 格式化回應訊息
        start_time = datetime.fromisoformat(event['start']['dateTime'].replace('Z', '+00:00'))
        end_time = datetime.fromisoformat(event['end']['dateTime'].replace('Z', '+00:00'))
        
        message = "✅ 已成功建立行程！\n\n"
        message += f"📅 日期：{start_time.strftime('%Y-%m-%d')}\n"
        message += f"⏰ 時間：{start_time.strftime('%H:%M')} - {end_time.strftime('%H:%M')}\n"
        message += f"📝 內容：{event['summary']}\n\n"
        message += f"🔗 查看行程：{event.get('htmlLink')}"
        
        return message
        
    except Exception as e:
        logger.error(f"新增行程時發生錯誤: {str(e)}")
        return "新增行程時發生錯誤，請稍後再試"

def handle_event_query(user_id, text, reply_token):
    """處理行程查詢"""
    try:
        # 解析日期
        date = parse_date_query(text)
        if not date:
            send_line_message(reply_token, "無法識別日期，請使用以下格式：\n今天、明天、後天、週一、下週三、12/25、2024/1/1")
            return

        # 獲取使用者授權
        credentials = get_user_credentials(user_id)
        if not credentials:
            send_line_message(reply_token, "請先完成 Google 日曆授權。")
            return

        # 建立 Google Calendar 服務
        service = build('calendar', 'v3', credentials=credentials)

        # 設定時間範圍
        time_min = datetime.combine(date, datetime.min.time()).isoformat() + 'Z'
        time_max = datetime.combine(date, datetime.max.time()).isoformat() + 'Z'

        # 查詢行程
        events_result = service.events().list(
            calendarId='primary',
            timeMin=time_min,
            timeMax=time_max,
            singleEvents=True,
            orderBy='startTime'
        ).execute()
        events = events_result.get('items', [])

        if not events:
            send_line_message(reply_token, f"{date.strftime('%Y-%m-%d')} 沒有行程。")
            return

        # 建立回覆訊息
        message = f"📅 {date.strftime('%Y-%m-%d')} 的行程：\n\n"
        
        for i, event in enumerate(events, 1):
            start = event['start'].get('dateTime', event['start'].get('date'))
            end = event['end'].get('dateTime', event['end'].get('date'))
            
            # 格式化時間
            if 'T' in start:
                start_time = datetime.fromisoformat(start.replace('Z', '+00:00')).strftime('%H:%M')
                end_time = datetime.fromisoformat(end.replace('Z', '+00:00')).strftime('%H:%M')
                time_str = f"⏰ {start_time} - {end_time}"
            else:
                time_str = "⏰ 全天"
            
            message += f"{i}. {time_str}\n"
            message += f"   📝 {event['summary']}\n"
            if 'description' in event:
                message += f"   📋 {event['description']}\n"
            message += "\n"
        
        message += "\n💡 提示：\n"
        message += "使用「修改行程 [編號] [新時間]」來修改行程\n"
        message += "使用「刪除行程 [編號]」來刪除行程"
        
        send_line_message(reply_token, message)
    except Exception as e:
        logger.error(f"查詢行程時發生錯誤: {str(e)}")
        send_line_message(reply_token, "查詢行程時發生錯誤，請稍後再試。")
        return

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if verify_admin(username, password):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('帳號或密碼錯誤')
            return redirect(url_for('admin_login'))
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    users = get_all_users()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/change_password', methods=['POST'])
def change_admin_password():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'message': '請先登入'}), 401
    
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not all([current_password, new_password, confirm_password]):
        return jsonify({'success': False, 'message': '所有欄位都必須填寫'}), 400
    
    if new_password != confirm_password:
        return jsonify({'success': False, 'message': '新密碼與確認密碼不符'}), 400
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # 驗證當前密碼
        cursor.execute('SELECT username, password FROM admins LIMIT 1')
        admin = cursor.fetchone()
        if not check_password_hash(admin['password'], current_password):
            return jsonify({'success': False, 'message': '當前密碼錯誤'}), 400
        
        # 更新密碼
        new_password_hash = generate_password_hash(new_password)
        cursor.execute('UPDATE admins SET password = ? WHERE username = ?',
                      (new_password_hash, admin['username']))
        conn.commit()
        return jsonify({'success': True, 'message': '密碼已成功更新'})
    except Exception as e:
        logger.error(f'更新管理員密碼時發生錯誤: {str(e)}')
        return jsonify({'success': False, 'message': '更新密碼時發生錯誤'}), 500
    finally:
        conn.close()

@app.route('/admin/delete_user/<line_user_id>', methods=['POST'])
def delete_user():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'message': '請先登入'}), 401
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # 刪除使用者相關資料
        cursor.execute('DELETE FROM events WHERE line_user_id = ?', (line_user_id,))
        cursor.execute('DELETE FROM orders WHERE line_user_id = ?', (line_user_id,))
        cursor.execute('DELETE FROM users WHERE line_user_id = ?', (line_user_id,))
        conn.commit()
        return jsonify({'success': True, 'message': '使用者已成功刪除'})
    except Exception as e:
        logger.error(f'刪除使用者時發生錯誤: {str(e)}')
        return jsonify({'success': False, 'message': '刪除使用者時發生錯誤'}), 500
    finally:
        conn.close()

@app.route('/oauth2callback')
@with_db_connection
def oauth2callback(conn):
    """處理 Google OAuth 回調"""
    try:
        # 獲取授權碼和狀態
        code = request.args.get('code')
        state = request.args.get('state')
        
        if not code or not state:
            return "授權失敗：缺少必要的參數", 400
        
        # 從狀態中獲取用戶 ID
        line_user_id = state
        
        # 獲取應用程式 URL
        app_url = os.getenv('APP_URL', 'https://line-calendar-assistant.onrender.com').rstrip('/')
        if not app_url.startswith('https://'):
            app_url = f"https://{app_url.replace('http://', '')}"
        redirect_uri = f"{app_url}/oauth2callback"
        
        # 載入客戶端憑證
        credentials_json = os.getenv('GOOGLE_CREDENTIALS')
        if not credentials_json:
            return "未設定 GOOGLE_CREDENTIALS 環境變數", 500
            
        try:
            credentials_info = json.loads(credentials_json)
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                json.dump(credentials_info, temp_file)
                temp_file_path = temp_file.name
            
            # 建立 OAuth 流程
            flow = Flow.from_client_secrets_file(
                temp_file_path,
                SCOPES,
                redirect_uri=redirect_uri
            )
            os.unlink(temp_file_path)
            
            # 交換授權碼
            flow.fetch_token(code=code)
            credentials = flow.credentials
            
            # 儲存用戶憑證
            save_user_credentials(line_user_id, credentials)
            
            # 使用 OAuth2 userinfo endpoint 獲取用戶資訊
            userinfo_url = "https://www.googleapis.com/oauth2/v3/userinfo"
            headers = {'Authorization': f'Bearer {credentials.token}'}
            response = requests.get(userinfo_url, headers=headers)
            
            if response.status_code == 200:
                user_info = response.json()
                email = user_info.get('email')
                
                if email:
                    # 更新用戶的 Google 電子郵件
                    cursor = conn.cursor()
                    cursor.execute('UPDATE users SET google_email = ? WHERE line_user_id = ?', (email, line_user_id))
                    conn.commit()
                    
                    return render_template('oauth_success.html')
                else:
                    return "無法獲取用戶電子郵件", 500
            else:
                return "無法獲取用戶資訊", 500
            
        except json.JSONDecodeError:
            return "GOOGLE_CREDENTIALS 環境變數格式錯誤", 500
        except Exception as e:
            logger.error(f"處理 OAuth 回調時發生錯誤：{str(e)}")
            return f"授權失敗：{str(e)}", 500
            
    except Exception as e:
        logger.error(f"OAuth 回調發生未預期錯誤：{str(e)}")
        return f"系統錯誤：{str(e)}", 500

if __name__ == "__main__":
    logger.info("Starting Flask application...")
    logger.info(f"LINE_CHANNEL_ACCESS_TOKEN: {os.getenv('LINE_CHANNEL_ACCESS_TOKEN')[:10]}...")
    logger.info(f"LINE_CHANNEL_SECRET: {os.getenv('LINE_CHANNEL_SECRET')[:10]}...")
    init_db()
    users = get_all_users()
    logger.info(f"Current authorized users: {len(users)}")
    if users:
        logger.info("Authorized user IDs:")
        for user_id in users:
            logger.info(f"- {user_id}")
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port) 