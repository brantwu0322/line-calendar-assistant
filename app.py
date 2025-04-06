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
from pydub import AudioSegment
from linebot import LineBotApi
from linebot.models import TextMessage, AudioMessage
import opencc
import sqlite3
from functools import wraps
from datetime import datetime, timedelta
import pytz
from dotenv import load_dotenv
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

# 設定日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 載入環境變數
load_dotenv()

# 設定資料庫路徑
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.db')
logger.info(f"Database path: {DB_PATH}")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['WTF_CSRF_ENABLED'] = False  # 暫時禁用 CSRF 保護以進行調試
csrf = CSRFProtect(app)
Session(app)

# 初始化 LINE Bot
channel_secret = os.getenv('LINE_CHANNEL_SECRET')
channel_access_token = os.getenv('LINE_CHANNEL_ACCESS_TOKEN')

if not channel_secret or not channel_access_token:
    app.logger.error('LINE Bot 配置缺失')
    raise ValueError('LINE Bot 配置缺失')

app.logger.info('Starting Flask application...')
app.logger.info(f'LINE_CHANNEL_ACCESS_TOKEN: {channel_access_token[:10]}...')
app.logger.info(f'LINE_CHANNEL_SECRET: {channel_secret[:10]}...')
app.logger.info(f'GOOGLE_CALENDAR_ID: {os.getenv("GOOGLE_CALENDAR_ID")}')

configuration = Configuration(access_token=channel_access_token)
handler = WebhookHandler(channel_secret)

# Google Calendar API 設定
SCOPES = ['https://www.googleapis.com/auth/calendar']
API_SERVICE_NAME = 'calendar'
API_VERSION = 'v3'
CLIENT_SECRETS_FILE = 'client_secrets.json'

# 初始化簡體轉繁體轉換器
converter = opencc.OpenCC('s2twp')

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

def init_db():
    """初始化資料庫"""
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # 創建用戶表
        c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            line_user_id TEXT UNIQUE NOT NULL,
            google_credentials TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        
        # 檢查是否已存在管理員帳號
        c.execute('SELECT COUNT(*) FROM admins')
        admin_count = c.fetchone()[0]
        
        if admin_count == 0:
            # 創建默認管理員帳號
            default_username = 'admin'
            default_password = 'admin'  # 在實際環境中應使用更安全的密碼
            hashed_password = generate_password_hash(default_password)
            
            c.execute('INSERT INTO admins (username, password) VALUES (?, ?)',
                     (default_username, hashed_password))
            
            app.logger.info('已創建默認管理員帳號')
        
        conn.commit()
        app.logger.info('資料庫初始化完成')
        
    except Exception as e:
        app.logger.error(f'初始化資料庫時發生錯誤: {str(e)}')
        app.logger.error('詳細錯誤資訊：', exc_info=True)
        
    finally:
        if 'conn' in locals():
            conn.close()

# 在應用啟動時初始化資料庫
init_db()

def get_all_users():
    """獲取所有已授權的使用者"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT line_user_id FROM users')
        users = c.fetchall()
        conn.close()
        return [user[0] for user in users]
    except Exception as e:
        logger.error(f"Error getting users: {str(e)}")
        return []

# 獲取用戶認證
def get_user_credentials(line_user_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT google_credentials FROM users WHERE line_user_id = ?', (line_user_id,))
        result = c.fetchone()
        conn.close()
        
        if result:
            return Credentials.from_authorized_user_info(json.loads(result[0]))
        return None
    except Exception as e:
        logger.error(f"Error getting user credentials: {str(e)}")
        return None

# 保存用戶認證
def save_user_credentials(line_user_id, credentials):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('INSERT OR REPLACE INTO users (line_user_id, google_credentials) VALUES (?, ?)',
                  (line_user_id, json.dumps({
                      'token': credentials.token,
                      'refresh_token': credentials.refresh_token,
                      'token_uri': credentials.token_uri,
                      'client_id': credentials.client_id,
                      'client_secret': credentials.client_secret,
                      'scopes': credentials.scopes
                  })))
        conn.commit()
        conn.close()
        logger.info(f"Saved credentials for user: {line_user_id}")
    except Exception as e:
        logger.error(f"Error saving user credentials: {str(e)}")
        raise

def get_google_calendar_service(line_user_id=None):
    """取得使用者的 Google Calendar 服務"""
    try:
        if line_user_id:
            # 如果提供了 line_user_id，嘗試獲取用戶的憑證
            creds = get_user_credentials(line_user_id)
            if not creds:
                # 如果沒有憑證，返回授權 URL
                credentials_json = os.getenv('GOOGLE_CREDENTIALS')
                if not credentials_json:
                    return None, "未設定 GOOGLE_CREDENTIALS 環境變數"
                
                try:
                    credentials_info = json.loads(credentials_json)
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                        json.dump(credentials_info, temp_file)
                        temp_file_path = temp_file.name
                    
                    flow = Flow.from_client_secrets_file(
                        temp_file_path,
                        SCOPES,
                        redirect_uri=url_for('oauth2callback', line_user_id=line_user_id, _external=True)
                    )
                    os.unlink(temp_file_path)
                    authorization_url, _ = flow.authorization_url(
                        access_type='offline',
                        include_granted_scopes='true'
                    )
                    return None, authorization_url
                except json.JSONDecodeError:
                    return None, "GOOGLE_CREDENTIALS 環境變數格式錯誤"
                except Exception as e:
                    logging.error(f"初始化 Google Calendar 流程時發生錯誤：{str(e)}")
                    return None, f"無法初始化 Google Calendar 授權流程：{str(e)}"
            
            try:
                credentials = Credentials.from_authorized_user_info(creds)
                if credentials and credentials.expired and credentials.refresh_token:
                    credentials.refresh(Request())
                    save_user_credentials(line_user_id, credentials)
                service = build('calendar', 'v3', credentials=credentials)
                return service, None
            except Exception as e:
                logging.error(f"取得 Google Calendar 服務時發生錯誤：{str(e)}")
                return None, "Google Calendar 服務發生錯誤"
        else:
            # 如果沒有提供 line_user_id，使用環境變數中的憑證
            credentials_json = os.getenv('GOOGLE_CREDENTIALS')
            if not credentials_json:
                return None, "未設定 GOOGLE_CREDENTIALS 環境變數"
            
            try:
                credentials_info = json.loads(credentials_json)
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                    json.dump(credentials_info, temp_file)
                    temp_file_path = temp_file.name
                
                flow = Flow.from_client_secrets_file(temp_file_path, SCOPES)
                os.unlink(temp_file_path)
                return flow, None
            except json.JSONDecodeError:
                return None, "GOOGLE_CREDENTIALS 環境變數格式錯誤"
            except Exception as e:
                logging.error(f"初始化 Google Calendar 流程時發生錯誤：{str(e)}")
                return None, f"無法初始化 Google Calendar 授權流程：{str(e)}"
    except Exception as e:
        logging.error(f"Google Calendar 服務發生未預期錯誤：{str(e)}")
        return None, f"系統錯誤：{str(e)}"

# OpenAI API 設定
openai.api_key = os.getenv('OPENAI_API_KEY')

# Google Calendar API 設定
SCOPES = ['https://www.googleapis.com/auth/calendar']

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
                    1. 輸入：「明天下午兩點跟客戶開會」
                       輸出：{
                           "date_type": "明天",
                           "time_period": "下午",
                           "hour": "2",
                           "minute": "0",
                           "is_recurring": false,
                           "recurrence_count": null,
                           "summary": "跟客戶開會"
                       }
                    
                    2. 輸入：「下週三早上九點去看牙醫」
                       輸出：{
                           "date_type": "下週三",
                           "time_period": "上午",
                           "hour": "9",
                           "minute": "0",
                           "is_recurring": false,
                           "recurrence_count": null,
                           "summary": "去看牙醫"
                       }
                    
                    3. 輸入：「每週五下午三點做瑜珈」
                       輸出：{
                           "date_type": "下週五",
                           "time_period": "下午",
                           "hour": "3",
                           "minute": "0",
                           "is_recurring": true,
                           "recurrence_count": 1,
                           "summary": "做瑜珈"
                       }
                    
                    4. 輸入：「三天後下午四點半打籃球」
                       輸出：{
                           "date_type": "3天後",
                           "time_period": "下午",
                           "hour": "4",
                           "minute": "30",
                           "is_recurring": false,
                           "recurrence_count": null,
                           "summary": "打籃球"
                       }
                    
                    5. 輸入：「連續四個禮拜的週一早上九點開會」
                       輸出：{
                           "date_type": "連續4個週一",
                           "time_period": "上午",
                           "hour": "9",
                           "minute": "0",
                           "is_recurring": true,
                           "recurrence_count": 4,
                           "summary": "開會"
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
            
            # 先找到下一個目標週幾
            days_until_next = (target_weekday - current_weekday) % 7
            if days_until_next == 0:
                days_until_next = 7
            
            # 計算到下週的天數
            days_to_next_week = 7 - current_weekday
            
            # 確保是下週的日期
            target_date = today + timedelta(days=days_to_next_week + target_weekday)
            
            logger.info(f"計算下週日期：今天是週{current_weekday + 1}，目標是週{target_weekday + 1}，到下週需要{days_to_next_week}天")
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
        
        start_time = datetime.combine(target_date, datetime_time(hour, minute))
        end_time = start_time + timedelta(hours=1)
        
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

def create_calendar_event(service, event_data):
    """建立 Google Calendar 事件"""
    try:
        logger.info("開始建立 Google Calendar 事件")
        logger.info(f"事件資料：{json.dumps(event_data, ensure_ascii=False)}")
        
        logger.info("準備建立事件")
        # 使用 'primary' 代表使用者的主要日曆
        event = service.events().insert(calendarId='primary', body=event_data).execute()
        logger.info(f"成功建立事件: {event.get('htmlLink')}")
        return True, event.get('htmlLink')
    except Exception as e:
        logger.error(f"建立事件時發生錯誤: {str(e)}")
        logger.exception("詳細錯誤資訊：")
        return False, str(e)

def parse_datetime_and_summary(text):
    """解析文字訊息中的日期時間和摘要"""
    try:
        # 使用 OpenAI API 解析文字
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "你是一個專業的日期時間解析助手。請從文字中提取日期時間和事件摘要。"},
                {"role": "user", "content": f"請從以下文字中提取日期時間和事件摘要：{text}"}
            ]
        )
        
        # 解析回應
        result = response.choices[0].message.content
        app.logger.info(f"OpenAI 解析結果: {result}")
        
        # 提取日期時間和摘要
        datetime_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2})'
        match = re.search(datetime_pattern, result)
        if match:
            parsed_datetime = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M')
            summary = result.split('\n')[0].strip()
            is_recurring = '重複' in result or '每週' in result or '每月' in result
            return parsed_datetime, summary, is_recurring
        else:
            return None, None, False
    except Exception as e:
        app.logger.error(f"解析日期時間時發生錯誤: {str(e)}")
        return None, None, False

@app.route('/callback', methods=['POST'])
def callback():
    """處理 LINE Bot 的回調請求"""
    try:
        app.logger.info('收到 LINE 回調請求')
        signature = request.headers['X-Line-Signature']
        body = request.get_data(as_text=True)
        
        # 驗證簽名
        handler.handle(body, signature)
        
        # 解析事件
        events = json.loads(body)['events']
        for event in events:
            if event['type'] == 'message' and event['message']['type'] == 'text':
                handle_message(event)
        
        app.logger.info('成功處理 LINE 回調請求')
        return 'OK'
    except InvalidSignatureError:
        app.logger.error('無效的簽名')
        abort(400)
    except Exception as e:
        app.logger.error(f'處理回調時發生錯誤: {str(e)}')
        abort(500)

def handle_message(event):
    """處理文字訊息"""
    try:
        text = event['message']['text']
        user_id = event['source']['userId']
        app.logger.info(f'收到文字訊息: {text}')
        
        # 解析日期時間和摘要
        app.logger.info(f'正在解析文字: {text}')
        parsed_datetime, summary, is_recurring = parse_datetime_and_summary(text)
        
        if parsed_datetime and summary:
            # 檢查用戶是否已授權
            if not is_user_authorized(user_id):
                reply_text = f"您需要先授權 Google Calendar 才能使用此功能。\n請點擊以下連結進行授權：\n{get_authorization_url(user_id)}"
            else:
                # 創建日曆事件
                event_id = create_calendar_event(user_id, parsed_datetime, summary, is_recurring)
                if event_id:
                    reply_text = f"已成功創建日曆事件：\n{summary}\n時間：{parsed_datetime.strftime('%Y-%m-%d %H:%M')}"
                else:
                    reply_text = "創建日曆事件失敗，請稍後再試。"
        else:
            reply_text = "無法識別日期時間，請使用以下格式：\n'週五下午三點開會' 或 '明天上午十點會議'"
        
        # 回覆用戶
        reply_message(event['replyToken'], reply_text)
        
    except Exception as e:
        app.logger.error(f'處理訊息時發生錯誤: {str(e)}')
        app.logger.error(f'詳細錯誤資訊：\n{traceback.format_exc()}')
        try:
            reply_message(event['replyToken'], "處理您的訊息時發生錯誤，請稍後再試。")
        except Exception as e:
            app.logger.error(f'發送錯誤訊息時也發生錯誤: {str(e)}')
            app.logger.error(f'詳細錯誤資訊：\n{traceback.format_exc()}')

def reply_message(reply_token, text):
    """回覆 LINE 訊息"""
    try:
        if not text:
            app.logger.error('嘗試發送空訊息')
            return
            
        messaging_api = MessagingApi(Configuration(access_token=channel_access_token))
        messaging_api.reply_message(
            ReplyMessageRequest(
                reply_token=reply_token,
                messages=[TextMessage(text=text)]
            )
        )
    except Exception as e:
        app.logger.error(f'發送訊息時發生錯誤: {str(e)}')
        raise

@handler.add(MessageEvent, message=TextMessageContent)
def handle_message(event):
    try:
        user_id = event.source.user_id
        text = event.message.text
        app.logger.info(f"收到文字訊息: {text}")
        app.logger.debug(f"事件詳情: {event}")

        # 檢查是否為測試消息
        if text == "測試":
            reply_text = "收到測試訊息！LINE Bot 正常運作中。"
            app.logger.info(f"準備回覆訊息: {reply_text}")
            
            with ApiClient(configuration) as api_client:
                messaging_api = MessagingApi(api_client)
                response = messaging_api.reply_message(
                    ReplyMessageRequest(
                        reply_token=event.reply_token,
                        messages=[{
                            "type": "text",
                            "text": reply_text
                        }]
                    )
                )
            return

        # 解析日期時間
        app.logger.info(f"正在解析文字: {text}")
        parsed_datetime, summary, is_recurring = parse_datetime_and_summary(text)
        
        if not parsed_datetime:
            reply_text = "抱歉，我無法理解您指定的時間。請使用更明確的時間表達方式，例如：「明天下午3點開會」"
            with ApiClient(configuration) as api_client:
                messaging_api = MessagingApi(api_client)
                response = messaging_api.reply_message(
                    ReplyMessageRequest(
                        reply_token=event.reply_token,
                        messages=[{
                            "type": "text",
                            "text": reply_text
                        }]
                    )
                )
            return

        app.logger.info(f"解析結果: 日期={parsed_datetime}, 摘要={summary}, 重複={is_recurring}")

        # 檢查用戶是否已授權
        if not is_user_authorized(user_id):
            auth_url = get_authorization_url(user_id)
            reply_text = f"請先授權我訪問您的 Google 日曆：\n{auth_url}"
            
            with ApiClient(configuration) as api_client:
                messaging_api = MessagingApi(api_client)
                response = messaging_api.reply_message(
                    ReplyMessageRequest(
                        reply_token=event.reply_token,
                        messages=[{
                            "type": "text",
                            "text": reply_text
                        }]
                    )
                )
            return

        # 創建日曆事件
        calendar_service = get_google_calendar_service(user_id)
        if not calendar_service:
            reply_text = "無法連接到 Google 日曆服務，請重新授權：" + get_authorization_url(user_id)
            
            with ApiClient(configuration) as api_client:
                messaging_api = MessagingApi(api_client)
                response = messaging_api.reply_message(
                    ReplyMessageRequest(
                        reply_token=event.reply_token,
                        messages=[{
                            "type": "text",
                            "text": reply_text
                        }]
                    )
                )
            return

        event_link = create_calendar_event(calendar_service, parsed_datetime)
        app.logger.info(f"成功建立事件: {event_link}")

        reply_text = f"已成功建立行程：{summary}\n{event_link}"
        app.logger.info(f"準備回覆訊息: {reply_text}")
        
        with ApiClient(configuration) as api_client:
            messaging_api = MessagingApi(api_client)
            response = messaging_api.reply_message(
                ReplyMessageRequest(
                    reply_token=event.reply_token,
                    messages=[{
                        "type": "text",
                        "text": reply_text
                    }]
                )
            )

    except Exception as e:
        app.logger.error(f"處理訊息時發生錯誤: {str(e)}")
        app.logger.error("詳細錯誤資訊：", exc_info=True)
        
        error_message = "抱歉，處理您的請求時發生錯誤。請稍後再試。"
        try:
            with ApiClient(configuration) as api_client:
                messaging_api = MessagingApi(api_client)
                response = messaging_api.reply_message(
                    ReplyMessageRequest(
                        reply_token=event.reply_token,
                        messages=[{
                            "type": "text",
                            "text": error_message
                        }]
                    )
                )
        except Exception as reply_error:
            app.logger.error(f"發送錯誤訊息時也發生錯誤: {str(reply_error)}")
            app.logger.error("詳細錯誤資訊：", exc_info=True)

    app.logger.info("成功處理 LINE 回調請求")

@handler.add(MessageEvent, message=AudioMessageContent)
@require_authorization
def handle_audio_message(event, service):
    """處理語音訊息"""
    temp_audio_path = None
    wav_path = None
    try:
        # 下載音訊檔案
        message_content = messaging_api.get_message_content(event.message.id)
        temp_audio_path = tempfile.mktemp(suffix='.m4a')
        wav_path = tempfile.mktemp(suffix='.wav')
        
        try:
            with open(temp_audio_path, 'wb') as f:
                for chunk in message_content.iter_content():
                    f.write(chunk)
            logging.info(f"成功下載音訊檔案，大小：{os.path.getsize(temp_audio_path)} bytes")
        except Exception as e:
            logging.error(f"下載音訊檔案時發生錯誤：{str(e)}")
            raise Exception("下載音訊檔案失敗")

        try:
            # 使用 pydub 轉換音訊格式
            audio = AudioSegment.from_file(temp_audio_path)
            audio = audio.set_frame_rate(16000)
            audio = audio.set_channels(1)
            audio.export(wav_path, format="wav")
            logging.info(f"成功轉換音訊格式：{wav_path}")
        except Exception as e:
            logging.error(f"轉換音訊格式時發生錯誤：{str(e)}")
            raise Exception("轉換音訊格式失敗")

        try:
            # 使用 SpeechRecognition 進行語音識別
            recognizer = sr.Recognizer()
            with sr.AudioFile(wav_path) as source:
                audio_data = recognizer.record(source)
                text = recognizer.recognize_google(audio_data, language='zh-TW')
                # 將簡體中文轉換為繁體中文
                text = converter.convert(text)
                logging.info(f"成功識別語音內容（繁體）：{text}")
        except sr.UnknownValueError:
            logging.error("無法識別語音內容")
            raise Exception("無法識別語音內容")
        except sr.RequestError as e:
            logging.error(f"語音識別服務發生錯誤：{str(e)}")
            raise Exception("語音識別服務暫時無法使用")

        # 處理識別出的文字
        try:
            # 檢查是否為行程相關訊息
            time_keywords = ["點", "時", "早上", "上午", "下午", "晚上", "明天", "後天", "大後天", "下週", "下下週", "天後"]
            if any(keyword in text for keyword in time_keywords):
                logging.info("開始處理行程訊息")
                # 解析事件資訊
                event_info = parse_event_text(text)
                logging.info(f"解析結果: {event_info}")
                
                if event_info:
                    logging.info("成功解析事件資訊，開始建立事件")
                    # 建立事件
                    success, result = create_calendar_event(service, event_info)
                    if success:
                        logging.info(f"成功建立事件，結果: {result}")
                        # 使用 GPT-4 生成回覆訊息
                        response = openai.ChatCompletion.create(
                            model="gpt-4",
                            messages=[
                                {
                                    "role": "system",
                                    "content": "你是一個友善的 LINE 聊天機器人助手。當用戶設定行程時，請用親切、生活化的語氣回覆，並加入一些貼心的提醒。"
                                },
                                {
                                    "role": "user",
                                    "content": f"我已經幫用戶設定了以下行程：\n事件：{event_info['summary']}\n時間：{event_info['start']['dateTime']} - {event_info['end']['dateTime']}\n請用親切、生活化的語氣回覆，並加入一些貼心的提醒。"
                                }
                            ],
                            temperature=0.7
                        )
                        reply_text = response.choices[0].message.content
                        logging.info(f"GPT-4 生成的回覆：{reply_text}")
                        messaging_api.reply_message_with_http_info(
                            ReplyMessageRequest(
                                reply_token=event.reply_token,
                                messages=[TextMessage(text=reply_text)]
                            )
                        )
                    else:
                        logging.error("建立事件失敗")
                        messaging_api.reply_message_with_http_info(
                            ReplyMessageRequest(
                                reply_token=event.reply_token,
                                messages=[TextMessage(text="抱歉，建立行程時發生錯誤。")]
                            )
                        )
                else:
                    logging.error("無法解析事件資訊")
                    messaging_api.reply_message_with_http_info(
                        ReplyMessageRequest(
                            reply_token=event.reply_token,
                            messages=[TextMessage(text="抱歉，我無法理解您的行程資訊。請使用以下格式：\n1. 明天下午兩點跟客戶開會\n2. 下週三早上九點去看牙醫\n3. 每週五下午三點做瑜珈\n4. 三天後下午四點半打籃球")]
                        )
                    )
            else:
                logging.info("收到一般語音訊息，使用 GPT-4 處理")
                # 使用 GPT-4 處理一般訊息
                response = openai.ChatCompletion.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "你是一個友善的 LINE 聊天機器人助手，請用簡短、親切的語氣回答。"},
                        {"role": "user", "content": text}
                    ]
                )
                reply_text = response.choices[0].message.content
                logging.info(f"GPT-4 回應: {reply_text}")
                messaging_api.reply_message_with_http_info(
                    ReplyMessageRequest(
                        reply_token=event.reply_token,
                        messages=[TextMessage(text=reply_text)]
                    )
                )
        except Exception as e:
            logging.error(f"處理識別文字時發生錯誤：{str(e)}")
            raise Exception("處理語音內容失敗")

    except Exception as e:
        logging.error(f"處理語音訊息時發生錯誤：{str(e)}")
        messaging_api.reply_message_with_http_info(
            ReplyMessageRequest(
                reply_token=event.reply_token,
                messages=[TextMessage(text="抱歉，處理語音訊息時發生錯誤。請稍後再試，或改用文字訊息。")]
            )
        )
    finally:
        # 清理臨時檔案
        for file_path in [temp_audio_path, wav_path]:
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    logging.info(f"成功刪除臨時檔案：{file_path}")
                except Exception as e:
                    logging.error(f"刪除臨時檔案時發生錯誤：{str(e)}")

# 新增授權相關路由
@app.route('/authorize/<line_user_id>')
def authorize(line_user_id):
    """處理 Google Calendar 授權"""
    try:
        # 初始化 OAuth 流程
        flow, error = get_google_calendar_service()
        if error:
            logger.error(f"初始化 OAuth 流程失敗：{error}")
            return render_template('error.html', error=f"無法初始化授權流程：{error}"), 500
            
        # 設置回調 URL
        flow.redirect_uri = url_for('oauth2callback', line_user_id=line_user_id, _external=True)
        
        # 生成授權 URL
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        
        # 保存狀態
        session['state'] = state
        session['line_user_id'] = line_user_id
        
        logger.info(f"生成授權 URL 成功：{authorization_url}")
        return redirect(authorization_url)
    except Exception as e:
        logger.error(f"授權過程發生錯誤：{str(e)}")
        return render_template('error.html', error="授權過程發生錯誤，請稍後再試"), 500

@app.route('/oauth2callback/<line_user_id>')
def oauth2callback(line_user_id):
    """處理 OAuth2 回調"""
    try:
        state = session.get('state')
        if not state:
            logger.error("Session state not found")
            return render_template('error.html', error="授權狀態無效，請重新開始授權流程"), 400

        # 從環境變數獲取憑證
        credentials_json = os.getenv('GOOGLE_CREDENTIALS')
        if not credentials_json:
            logger.error("GOOGLE_CREDENTIALS not found in environment variables")
            return render_template('error.html', error="系統設定錯誤，請聯繫管理員"), 500

        # 創建臨時憑證文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            json.dump(json.loads(credentials_json), temp_file)
            temp_file_path = temp_file.name

        try:
            flow = InstalledAppFlow.from_client_secrets_file(
                temp_file_path,
                ['https://www.googleapis.com/auth/calendar'],
                state=state
            )
            flow.redirect_uri = url_for('oauth2callback', line_user_id=line_user_id, _external=True)
            
            authorization_response = request.url
            flow.fetch_token(authorization_response=authorization_response)
            credentials = flow.credentials
            
            # 儲存認證資訊
            save_user_credentials(line_user_id, credentials)
            
            logger.info(f"Successfully authorized user: {line_user_id}")
            return render_template('success.html', message="授權成功！請回到 LINE 繼續使用。")
        finally:
            # 清理臨時文件
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
                logger.info(f"Cleaned up temporary file: {temp_file_path}")
    except Exception as e:
        logger.error(f"Error in oauth2callback: {str(e)}")
        logger.exception("Detailed error information:")
        return render_template('error.html', error="授權過程發生錯誤，請稍後再試"), 500

def verify_admin(username, password):
    """驗證管理員帳號密碼"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT password FROM admins WHERE username = ?', (username,))
        result = c.fetchone()
        conn.close()
        
        if result:
            return check_password_hash(result[0], password)
        return False
    except Exception as e:
        app.logger.error(f"驗證管理員時發生錯誤: {str(e)}")
        return False

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('請輸入帳號和密碼')
            return render_template('admin_login.html')
        
        if verify_admin(username, password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            app.logger.info(f'管理員 {username} 登入成功')
            return redirect(url_for('admin_dashboard'))
        else:
            app.logger.warning(f'管理員登入失敗: {username}')
            flash('帳號或密碼錯誤')
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # 檢查資料庫連接
        c.execute('SELECT 1')
        if not c.fetchone():
            raise Exception("資料庫連接測試失敗")
            
        # 獲取使用者資料
        c.execute('''SELECT line_user_id, created_at, updated_at 
                     FROM users 
                     ORDER BY created_at DESC''')
        users = c.fetchall()
        conn.close()
        
        app.logger.info(f'成功獲取 {len(users)} 位使用者資料')
        return render_template('admin_dashboard.html', 
                             users=users,
                             admin_username=session.get('admin_username'))
    except Exception as e:
        app.logger.error(f'管理後臺發生錯誤: {str(e)}')
        app.logger.error(f'詳細錯誤資訊：\n{traceback.format_exc()}')
        return render_template('error.html', error="資料庫存取錯誤"), 500

@app.route('/admin/logout')
def admin_logout():
    """管理員登出"""
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('已成功登出')
    return redirect(url_for('admin_login'))

# 訂閱相關路由
@app.route('/subscribe/<line_user_id>')
def subscribe(line_user_id):
    """處理訂閱請求"""
    # 這裡可以整合金流系統（如綠界、藍新等）
    # 目前先模擬訂閱流程
    order_id = create_order(line_user_id, 299)  # 假設月費 299 元
    
    if order_id:
        # 這裡應該導向金流系統的付款頁面
        # 目前先模擬付款成功
        update_user_subscription(line_user_id, 'premium', 
                               (datetime.now() + timedelta(days=30)).isoformat())
        return "訂閱成功！請回到 LINE 繼續使用。"
    return "訂閱失敗，請稍後再試。"

def get_user_status(line_user_id):
    """獲取使用者狀態"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''SELECT subscription_status, subscription_end_date 
                     FROM users WHERE line_user_id = ?''', (line_user_id,))
        result = c.fetchone()
        conn.close()
        
        if result:
            return {
                'status': result[0],
                'end_date': result[1]
            }
        return None
    except Exception as e:
        logger.error(f"Error getting user status: {str(e)}")
        return None

def update_user_subscription(line_user_id, status, end_date):
    """更新使用者訂閱狀態"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''UPDATE users 
                     SET subscription_status = ?, subscription_end_date = ?
                     WHERE line_user_id = ?''', (status, end_date, line_user_id))
        conn.commit()
        conn.close()
        logger.info(f"Updated subscription for user: {line_user_id}")
        return True
    except Exception as e:
        logger.error(f"Error updating user subscription: {str(e)}")
        return False

def create_order(line_user_id, amount):
    """建立訂單"""
    try:
        order_id = f"ORDER_{int(time.time())}_{line_user_id[:8]}"
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT INTO orders (order_id, line_user_id, amount, status)
                     VALUES (?, ?, ?, ?)''', (order_id, line_user_id, amount, 'pending'))
        conn.commit()
        conn.close()
        return order_id
    except Exception as e:
        logger.error(f"Error creating order: {str(e)}")
        return None

def init_admin():
    """初始化管理員帳號"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # 檢查是否已存在管理員帳號
        c.execute('SELECT COUNT(*) FROM admins')
        if c.fetchone()[0] == 0:
            # 創建預設管理員帳號
            c.execute('''INSERT INTO admins (username, password)
                        VALUES (?, ?)''', ('admin', 'admin'))
            conn.commit()
            logger.info("Created default admin account")
        
        conn.close()
    except Exception as e:
        logger.error(f"Error initializing admin account: {str(e)}")

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error="找不到該頁面"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error="伺服器內部錯誤"), 500

if __name__ == "__main__":
    logger.info("Starting Flask application...")
    logger.info(f"LINE_CHANNEL_ACCESS_TOKEN: {os.getenv('LINE_CHANNEL_ACCESS_TOKEN')[:10]}...")
    logger.info(f"LINE_CHANNEL_SECRET: {os.getenv('LINE_CHANNEL_SECRET')[:10]}...")
    init_db()
    init_admin()  # 初始化管理員帳號
    users = get_all_users()
    logger.info(f"Current authorized users: {len(users)}")
    if users:
        logger.info("Authorized user IDs:")
        for user_id in users:
            logger.info(f"- {user_id}")
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port) 