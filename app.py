import os
import json
import logging
import openai
from openai import OpenAI
from datetime import datetime, timedelta
from flask import Flask, request, abort, render_template, redirect, url_for, session, jsonify
from linebot.v3 import WebhookHandler
from linebot.v3.exceptions import InvalidSignatureError
from linebot.v3.messaging import (
    Configuration,
    ApiClient,
    MessagingApi,
    ReplyMessageRequest,
    TextMessage
)
from linebot.v3.webhooks import (
    MessageEvent,
    TextMessageContent
)
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import pickle
import os.path
import re
import pytz
import requests
import time
from dotenv import load_dotenv
import sqlite3
from functools import wraps
import hashlib

# 載入環境變數
load_dotenv()

# 設定日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 初始化 LINE Bot
configuration = Configuration(access_token=os.getenv('LINE_CHANNEL_ACCESS_TOKEN'))
handler = WebhookHandler(os.getenv('LINE_CHANNEL_SECRET'))

# 初始化 OpenAI
openai.api_key = os.getenv('OPENAI_API_KEY')
openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# 初始化 Flask 應用
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev')

# 設定時區
tz = pytz.timezone('Asia/Taipei')

# 管理員驗證裝飾器
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# 初始化資料庫
def init_db():
    with sqlite3.connect('database.db') as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                line_user_id TEXT PRIMARY KEY,
                google_email TEXT,
                google_credentials TEXT,
                auth_state TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

# 初始化資料庫連接
def get_db():
    db = sqlite3.connect('database.db')
    db.row_factory = sqlite3.Row
    return db

# 初始化資料庫
init_db()

# 從環境變數讀取 Google 憑證
def get_google_credentials_from_env():
    try:
        credentials_json = os.getenv('GOOGLE_CREDENTIALS')
        if not credentials_json:
            raise ValueError("GOOGLE_CREDENTIALS 環境變數未設定")
        return json.loads(credentials_json)
    except Exception as e:
        logger.error(f"從環境變數讀取 Google 憑證時發生錯誤: {e}")
        return None

# 檢查並更新 Google 授權
def check_and_refresh_google_credentials(user_id):
    try:
        db = get_db()
        cursor = db.execute("SELECT google_credentials FROM users WHERE line_user_id = ?", (user_id,))
        result = cursor.fetchone()
        
        if not result or not result['google_credentials']:
            return None

        credentials = pickle.loads(result['google_credentials'])
        
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            db.execute(
                "UPDATE users SET google_credentials = ? WHERE line_user_id = ?",
                (pickle.dumps(credentials), user_id)
            )
            db.commit()
        
        return credentials
    except Exception as e:
        logger.error(f"更新 Google 授權時發生錯誤: {e}")
        return None

# 解析日期查詢
def parse_date_query(text):
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": """你是一個日期解析助手。請根據用戶的查詢，返回對應的日期。
                支援的格式：
                1. 日期格式：X/Y（如：4/9）
                2. 週幾格式：週X（如：週五）
                3. 下週格式：下週X（如：下週三）
                
                請返回 JSON 格式：
                {
                    "date": "YYYY-MM-DD",
                    "type": "exact" 或 "weekday" 或 "next_week"
                }"""},
                {"role": "user", "content": text}
            ]
        )
        
        result = json.loads(response.choices[0].message.content)
        return result
    except Exception as e:
        logger.error(f"解析日期時發生錯誤: {e}")
        return None

# 解析事件文字
def parse_event_text(text):
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": """你是一個事件解析助手。請從用戶的文字中提取事件資訊。
                請返回 JSON 格式：
                {
                    "summary": "事件標題",
                    "start": {
                        "dateTime": "YYYY-MM-DDTHH:MM:SS+08:00",
                        "timeZone": "Asia/Taipei"
                    },
                    "end": {
                        "dateTime": "YYYY-MM-DDTHH:MM:SS+08:00",
                        "timeZone": "Asia/Taipei"
                    },
                    "description": "事件描述"
                }"""},
                {"role": "user", "content": text}
            ]
        )
        
        result = json.loads(response.choices[0].message.content)
        return result
    except Exception as e:
        logger.error(f"解析事件時發生錯誤: {e}")
        return None

# 處理事件查詢
def handle_event_query(user_id, text):
    credentials = check_and_refresh_google_credentials(user_id)
    if not credentials:
        return "請先完成 Google 日曆授權"

    try:
        service = build('calendar', 'v3', credentials=credentials)
        
        # 解析日期
        date_info = parse_date_query(text)
        if not date_info:
            return "無法解析日期，請確認格式是否正確"

        # 設定查詢時間範圍
        if date_info['type'] == 'exact':
            start_date = datetime.strptime(date_info['date'], '%Y-%m-%d')
            end_date = start_date + timedelta(days=1)
        elif date_info['type'] == 'weekday':
            current_date = datetime.now(tz)
            target_weekday = int(date_info['date'].split('-')[2])
            days_ahead = (target_weekday - current_date.weekday()) % 7
            if days_ahead == 0:  # 如果是今天，顯示下週
                days_ahead = 7
            start_date = current_date + timedelta(days=days_ahead)
            end_date = start_date + timedelta(days=1)
        else:  # next_week
            current_date = datetime.now(tz)
            target_weekday = int(date_info['date'].split('-')[2])
            days_ahead = (target_weekday - current_date.weekday()) % 7
            days_ahead += 7  # 確保是下週
            start_date = current_date + timedelta(days=days_ahead)
            end_date = start_date + timedelta(days=1)

        # 查詢事件
        events_result = service.events().list(
            calendarId='primary',
            timeMin=start_date.isoformat(),
            timeMax=end_date.isoformat(),
            singleEvents=True,
            orderBy='startTime'
        ).execute()
        
        events = events_result.get('items', [])
        
        if not events:
            return f"{start_date.strftime('%Y-%m-%d')} 沒有行程"
        
        message = f"{start_date.strftime('%Y-%m-%d')} 的行程：\n\n"
        for event in events:
            start = event['start'].get('dateTime', event['start'].get('date'))
            end = event['end'].get('dateTime', event['end'].get('date'))
            
            if 'dateTime' in event['start']:
                start_time = datetime.fromisoformat(start.replace('Z', '+00:00')).astimezone(tz)
                end_time = datetime.fromisoformat(end.replace('Z', '+00:00')).astimezone(tz)
                message += f"⏰ {start_time.strftime('%H:%M')} - {end_time.strftime('%H:%M')}\n"
            else:
                message += "📅 全天\n"
            
            message += f"📝 {event['summary']}\n"
            if 'description' in event:
                message += f"📋 {event['description']}\n"
            message += "\n"
        
        return message
    except HttpError as e:
        logger.error(f"查詢日曆時發生錯誤: {e}")
        return "查詢日曆時發生錯誤，請稍後再試"

# 處理事件新增
def handle_event_addition(user_id, text):
    credentials = check_and_refresh_google_credentials(user_id)
    if not credentials:
        return "請先完成 Google 日曆授權"

    try:
        service = build('calendar', 'v3', credentials=credentials)
        
        # 解析事件
        event_info = parse_event_text(text)
        if not event_info:
            return "無法解析事件，請確認格式是否正確"

        # 新增事件
        event = service.events().insert(calendarId='primary', body=event_info).execute()
        
        return f"已新增行程：\n{event_info['summary']}\n時間：{event_info['start']['dateTime']}"
    except HttpError as e:
        logger.error(f"新增事件時發生錯誤: {e}")
        return "新增事件時發生錯誤，請稍後再試"

# 處理事件修改
def handle_event_modification(user_id, text):
    credentials = check_and_refresh_google_credentials(user_id)
    if not credentials:
        return "請先完成 Google 日曆授權"

    try:
        service = build('calendar', 'v3', credentials=credentials)
        
        # 解析日期
        date_info = parse_date_query(text)
        if not date_info:
            return "無法解析日期，請確認格式是否正確"

        # 設定查詢時間範圍
        if date_info['type'] == 'exact':
            start_date = datetime.strptime(date_info['date'], '%Y-%m-%d')
            end_date = start_date + timedelta(days=1)
        elif date_info['type'] == 'weekday':
            current_date = datetime.now(tz)
            target_weekday = int(date_info['date'].split('-')[2])
            days_ahead = (target_weekday - current_date.weekday()) % 7
            if days_ahead == 0:  # 如果是今天，顯示下週
                days_ahead = 7
            start_date = current_date + timedelta(days=days_ahead)
            end_date = start_date + timedelta(days=1)
        else:  # next_week
            current_date = datetime.now(tz)
            target_weekday = int(date_info['date'].split('-')[2])
            days_ahead = (target_weekday - current_date.weekday()) % 7
            days_ahead += 7  # 確保是下週
            start_date = current_date + timedelta(days=days_ahead)
            end_date = start_date + timedelta(days=1)

        # 查詢事件
        events_result = service.events().list(
            calendarId='primary',
            timeMin=start_date.isoformat(),
            timeMax=end_date.isoformat(),
            singleEvents=True,
            orderBy='startTime'
        ).execute()
        
        events = events_result.get('items', [])
        
        if not events:
            return f"{start_date.strftime('%Y-%m-%d')} 沒有行程可修改"
        
        message = f"{start_date.strftime('%Y-%m-%d')} 的行程：\n\n"
        for i, event in enumerate(events, 1):
            start = event['start'].get('dateTime', event['start'].get('date'))
            end = event['end'].get('dateTime', event['end'].get('date'))
            
            if 'dateTime' in event['start']:
                start_time = datetime.fromisoformat(start.replace('Z', '+00:00')).astimezone(tz)
                end_time = datetime.fromisoformat(end.replace('Z', '+00:00')).astimezone(tz)
                message += f"{i}. ⏰ {start_time.strftime('%H:%M')} - {end_time.strftime('%H:%M')}\n"
            else:
                message += f"{i}. 📅 全天\n"
            
            message += f"   📝 {event['summary']}\n"
            if 'description' in event:
                message += f"   📋 {event['description']}\n"
            message += "\n"
        
        message += "請輸入要修改的行程編號："
        return message
    except HttpError as e:
        logger.error(f"查詢日曆時發生錯誤: {e}")
        return "查詢日曆時發生錯誤，請稍後再試"

# 處理事件刪除
def handle_event_deletion(user_id, text):
    credentials = check_and_refresh_google_credentials(user_id)
    if not credentials:
        return "請先完成 Google 日曆授權"

    try:
        service = build('calendar', 'v3', credentials=credentials)
        
        # 解析日期
        date_info = parse_date_query(text)
        if not date_info:
            return "無法解析日期，請確認格式是否正確"

        # 設定查詢時間範圍
        if date_info['type'] == 'exact':
            start_date = datetime.strptime(date_info['date'], '%Y-%m-%d')
            end_date = start_date + timedelta(days=1)
        elif date_info['type'] == 'weekday':
            current_date = datetime.now(tz)
            target_weekday = int(date_info['date'].split('-')[2])
            days_ahead = (target_weekday - current_date.weekday()) % 7
            if days_ahead == 0:  # 如果是今天，顯示下週
                days_ahead = 7
            start_date = current_date + timedelta(days=days_ahead)
            end_date = start_date + timedelta(days=1)
        else:  # next_week
            current_date = datetime.now(tz)
            target_weekday = int(date_info['date'].split('-')[2])
            days_ahead = (target_weekday - current_date.weekday()) % 7
            days_ahead += 7  # 確保是下週
            start_date = current_date + timedelta(days=days_ahead)
            end_date = start_date + timedelta(days=1)

        # 查詢事件
        events_result = service.events().list(
            calendarId='primary',
            timeMin=start_date.isoformat(),
            timeMax=end_date.isoformat(),
            singleEvents=True,
            orderBy='startTime'
        ).execute()
        
        events = events_result.get('items', [])
        
        if not events:
            return f"{start_date.strftime('%Y-%m-%d')} 沒有行程可刪除"
        
        message = f"{start_date.strftime('%Y-%m-%d')} 的行程：\n\n"
        for i, event in enumerate(events, 1):
            start = event['start'].get('dateTime', event['start'].get('date'))
            end = event['end'].get('dateTime', event['end'].get('date'))
            
            if 'dateTime' in event['start']:
                start_time = datetime.fromisoformat(start.replace('Z', '+00:00')).astimezone(tz)
                end_time = datetime.fromisoformat(end.replace('Z', '+00:00')).astimezone(tz)
                message += f"{i}. ⏰ {start_time.strftime('%H:%M')} - {end_time.strftime('%H:%M')}\n"
            else:
                message += f"{i}. 📅 全天\n"
            
            message += f"   📝 {event['summary']}\n"
            if 'description' in event:
                message += f"   📋 {event['description']}\n"
            message += "\n"
        
        message += "請輸入要刪除的行程編號："
        return message
    except HttpError as e:
        logger.error(f"查詢日曆時發生錯誤: {e}")
        return "查詢日曆時發生錯誤，請稍後再試"

# 處理授權請求
def handle_authorization_request(user_id):
    try:
        # 從環境變數讀取憑證
        credentials_dict = get_google_credentials_from_env()
        if not credentials_dict:
            return "無法讀取 Google 憑證，請聯繫管理員"
        
        # 建立授權流程
        flow = InstalledAppFlow.from_client_config(
            credentials_dict,
            ['https://www.googleapis.com/auth/calendar']
        )
        flow.redirect_uri = os.getenv('GOOGLE_REDIRECT_URI', 'https://line-calendar-assistant.onrender.com/oauth2callback')
        
        # 產生授權 URL
        auth_url, _ = flow.authorization_url(prompt='consent')
        
        # 儲存授權狀態
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO users (line_user_id, auth_state) VALUES (?, ?) ON CONFLICT(line_user_id) DO UPDATE SET auth_state = excluded.auth_state",
                (user_id, flow.state)
            )
            db.commit()
        finally:
            db.close()
        
        return f"請點擊以下連結完成 Google 日曆授權：\n{auth_url}"
    except Exception as e:
        logger.error(f"產生授權 URL 時發生錯誤: {e}")
        return "產生授權 URL 時發生錯誤，請稍後再試"

# 處理授權回調
@app.route('/oauth2callback')
def oauth2callback():
    try:
        state = request.args.get('state')
        code = request.args.get('code')
        
        if not state or not code:
            return "授權失敗：缺少必要的參數"
        
        # 取得對應的用戶
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT line_user_id FROM users WHERE auth_state = ?", (state,))
        result = cursor.fetchone()
        
        if not result:
            return "授權失敗：找不到對應的用戶"
        
        user_id = result['line_user_id']
        
        # 從環境變數讀取憑證
        credentials_dict = get_google_credentials_from_env()
        if not credentials_dict:
            return "授權失敗：無法讀取 Google 憑證"
        
        # 建立授權流程
        flow = InstalledAppFlow.from_client_config(
            credentials_dict,
            ['https://www.googleapis.com/auth/calendar']
        )
        flow.redirect_uri = os.getenv('GOOGLE_REDIRECT_URI', 'https://line-calendar-assistant.onrender.com/oauth2callback')
        
        # 取得憑證
        flow.fetch_token(code=code)
        credentials = flow.credentials
        
        # 取得用戶的 Google 帳號資訊
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        email = user_info.get('email')
        
        # 儲存憑證和郵箱
        cursor.execute(
            "UPDATE users SET google_credentials = ?, google_email = ?, auth_state = NULL WHERE line_user_id = ?",
            (pickle.dumps(credentials), email, user_id)
        )
        db.commit()
        
        # 通知用戶
        with ApiClient(configuration) as api_client:
            line_bot_api = MessagingApi(api_client)
            line_bot_api.reply_message(
                ReplyMessageRequest(
                    reply_token=user_id,
                    messages=[TextMessage(text=f"Google 日曆授權成功！\n您的 Google 帳號：{email}")]
                )
            )
        
        return "授權成功！您可以關閉此視窗。"
    except Exception as e:
        logger.error(f"處理授權回調時發生錯誤: {e}")
        return "授權失敗，請稍後再試"

# 檢查用戶是否已授權
def is_authorized(user_id):
    try:
        db = get_db()
        user = db.execute(
            'SELECT google_credentials FROM users WHERE line_user_id = ?',
            (user_id,)
        ).fetchone()
        return user is not None and user['google_credentials'] is not None
    except Exception as e:
        logger.error(f"檢查授權狀態時發生錯誤: {str(e)}")
        return False

# 處理訊息
@app.route("/callback", methods=['POST'])
def callback():
    signature = request.headers['X-Line-Signature']
    body = request.get_data(as_text=True)
    
    try:
        handler.handle(body, signature)
    except InvalidSignatureError:
        abort(400)
    
    return 'OK'

@handler.add(MessageEvent, message=TextMessageContent)
def handle_message(event):
    try:
        # 取得用戶 ID
        user_id = event.source.user_id
        
        # 取得訊息內容
        text = event.message.text
        
        # 建立 MessagingApi 實例
        with ApiClient(configuration) as api_client:
            line_bot_api = MessagingApi(api_client)
            
            # 檢查是否需要授權
            if text == '授權':
                if not is_authorized(user_id):
                    # 建立授權 URL
                    auth_url = handle_authorization_request(user_id)
                    # 回傳授權 URL 給用戶
                    line_bot_api.reply_message(
                        ReplyMessageRequest(
                            reply_token=event.reply_token,
                            messages=[TextMessage(text=f'請點擊以下連結進行授權：\n{auth_url}')]
                        )
                    )
                else:
                    # 如果已經授權，提示用戶
                    line_bot_api.reply_message(
                        ReplyMessageRequest(
                            reply_token=event.reply_token,
                            messages=[TextMessage(text='您已經完成授權，不需要再次授權。')]
                        )
                    )
                return
            
            # 處理查詢行程
            if any(keyword in text for keyword in ['查詢行程', '查看行程', '我的行程']) or '的行程' in text:
                response = handle_event_query(user_id, text)
                line_bot_api.reply_message(
                    ReplyMessageRequest(
                        reply_token=event.reply_token,
                        messages=[TextMessage(text=response)]
                    )
                )
                return
            
            # 處理修改行程
            if any(keyword in text for keyword in ['修改行程', '更改行程', '更新行程']):
                response = handle_event_modification(user_id, text)
                line_bot_api.reply_message(
                    ReplyMessageRequest(
                        reply_token=event.reply_token,
                        messages=[TextMessage(text=response)]
                    )
                )
                return
            
            # 處理刪除行程
            if any(keyword in text for keyword in ['刪除行程', '移除行程', '取消行程']):
                response = handle_event_deletion(user_id, text)
                line_bot_api.reply_message(
                    ReplyMessageRequest(
                        reply_token=event.reply_token,
                        messages=[TextMessage(text=response)]
                    )
                )
                return
            
            # 處理新增行程
            if any(keyword in text for keyword in ['新增行程', '加入行程', '建立行程']):
                response = handle_event_addition(user_id, text)
                line_bot_api.reply_message(
                    ReplyMessageRequest(
                        reply_token=event.reply_token,
                        messages=[TextMessage(text=response)]
                    )
                )
                return
            
            # 處理取消授權
            if any(keyword in text for keyword in ['取消授權', '解除綁定', '斷開連結']):
                db = get_db()
                try:
                    cursor = db.cursor()
                    cursor.execute(
                        "UPDATE users SET google_credentials = NULL, google_email = NULL WHERE line_user_id = ?",
                        (user_id,)
                    )
                    db.commit()
                    line_bot_api.reply_message(
                        ReplyMessageRequest(
                            reply_token=event.reply_token,
                            messages=[TextMessage(text="已取消 Google 日曆授權")]
                        )
                    )
                finally:
                    db.close()
                return
            
            # 處理幫助訊息
            if any(keyword in text for keyword in ['幫助', '說明', '功能']):
                help_text = """📅 LINE 日曆助手使用說明：
                
1. 查詢行程
   - 格式：查詢 X/Y 的行程（如：查詢 4/9 的行程）
   - 格式：查詢週X的行程（如：查詢週五的行程）
   - 格式：查詢下週X的行程（如：查詢下週三的行程）

2. 新增行程
   - 格式：新增行程 [時間] [標題] [描述]
   - 範例：新增行程 明天下午2點 開會 討論專案進度

3. 修改行程
   - 格式：修改行程 [日期]
   - 範例：修改行程 4/9

4. 刪除行程
   - 格式：刪除行程 [日期]
   - 範例：刪除行程 4/9

5. 授權相關
   - 輸入「授權」開始 Google 日曆授權流程
   - 輸入「取消授權」解除 Google 日曆綁定"""
                
                line_bot_api.reply_message(
                    ReplyMessageRequest(
                        reply_token=event.reply_token,
                        messages=[TextMessage(text=help_text)]
                    )
                )
                return
            
            # 預設回應
            line_bot_api.reply_message(
                ReplyMessageRequest(
                    reply_token=event.reply_token,
                    messages=[TextMessage(text="請輸入「幫助」查看使用說明")]
                )
            )
    except Exception as e:
        logger.error(f"處理訊息時發生錯誤: {e}")
        with ApiClient(configuration) as api_client:
            line_bot_api = MessagingApi(api_client)
            line_bot_api.reply_message(
                ReplyMessageRequest(
                    reply_token=event.reply_token,
                    messages=[TextMessage(text="處理訊息時發生錯誤，請稍後再試")]
                )
            )

# 管理後台路由
@app.route('/admin')
def admin():
    # 檢查是否已登入
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    # 取得資料庫連接
    db = get_db()
    cursor = db.cursor()
    
    try:
        # 獲取搜尋參數
        search_term = request.args.get('search', '')
        
        # 獲取使用者統計
        cursor.execute("""
            SELECT 
                COUNT(*) as total_users,
                SUM(google_credentials IS NOT NULL) as authorized_users
            FROM users
        """)
        stats = cursor.fetchone()
        
        # 獲取使用者列表
        if search_term:
            cursor.execute(
                "SELECT line_user_id, google_email, google_credentials, created_at FROM users WHERE line_user_id LIKE ? OR google_email LIKE ? ORDER BY created_at DESC",
                (f'%{search_term}%', f'%{search_term}%')
            )
            users = cursor.fetchall()
        else:
            cursor.execute(
                "SELECT line_user_id, google_email, google_credentials, created_at FROM users ORDER BY created_at DESC"
            )
            users = cursor.fetchall()
            
        return render_template('admin_dashboard.html', 
                             users=users, 
                             stats=stats,
                             search_term=search_term,
                             admin_username=session.get('admin_username'))
    except Exception as e:
        logger.error(f"載入管理後台時發生錯誤: {str(e)}")
        return render_template('error.html', message='處理請求時發生錯誤')
    finally:
        db.close()

# 管理員登入路由
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            db = get_db()
            admin = db.execute(
                'SELECT * FROM admins WHERE username = ? AND password = ?',
                (username, hashlib.sha256(password.encode()).hexdigest())
            ).fetchone()
            
            if admin:
                session['admin_id'] = admin['username']
                return redirect(url_for('admin'))
            
            return render_template('admin_login.html', error='帳號或密碼錯誤')
        except Exception as e:
            logger.error(f"管理員登入時發生錯誤: {str(e)}")
            return render_template('admin_login.html', error='登入時發生錯誤')
    
    return render_template('admin_login.html')

# 修改管理員密碼路由
@app.route('/admin/change_password', methods=['POST'])
@admin_required
def change_password():
    try:
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_password or not new_password or not confirm_password:
            return jsonify({'success': False, 'message': '請填寫所有欄位'})
            
        if new_password != confirm_password:
            return jsonify({'success': False, 'message': '新密碼與確認密碼不符'})
            
        db = get_db()
        admin = db.execute(
            'SELECT * FROM admins WHERE username = ? AND password = ?',
            (session['admin_id'], current_password)
        ).fetchone()
        
        if not admin:
            return jsonify({'success': False, 'message': '當前密碼錯誤'})
            
        db.execute(
            'UPDATE admins SET password = ? WHERE username = ?',
            (new_password, session['admin_id'])
        )
        db.commit()
        
        return jsonify({'success': True, 'message': '密碼修改成功'})
    except Exception as e:
        logger.error(f"修改密碼時發生錯誤: {str(e)}")
        return jsonify({'success': False, 'message': '修改密碼時發生錯誤'})

# 新增管理員路由
@app.route('/admin/add', methods=['POST'])
@admin_required
def add_admin():
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return jsonify({'success': False, 'message': '請填寫所有欄位'})
            
        db = get_db()
        try:
            db.execute(
                'INSERT INTO admins (username, password) VALUES (?, ?)',
                (username, password)
            )
            db.commit()
            return jsonify({'success': True, 'message': '管理員新增成功'})
        except sqlite3.IntegrityError:
            return jsonify({'success': False, 'message': '該帳號已存在'})
    except Exception as e:
        logger.error(f"新增管理員時發生錯誤: {str(e)}")
        return jsonify({'success': False, 'message': '新增管理員時發生錯誤'})

# 刪除管理員路由
@app.route('/admin/delete/<username>', methods=['POST'])
@admin_required
def delete_admin(username):
    try:
        if username == session['admin_id']:
            return jsonify({'success': False, 'message': '不能刪除自己的帳號'})
            
        db = get_db()
        db.execute('DELETE FROM admins WHERE username = ?', (username,))
        db.commit()
        
        return jsonify({'success': True, 'message': '管理員刪除成功'})
    except Exception as e:
        logger.error(f"刪除管理員時發生錯誤: {str(e)}")
        return jsonify({'success': False, 'message': '刪除管理員時發生錯誤'})

# 管理員登出路由
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/query_user/<line_user_id>')
@admin_required
def query_user(line_user_id):
    try:
        db = get_db()
        user = db.execute(
            'SELECT line_user_id, google_email, google_credentials, created_at FROM users WHERE line_user_id = ?',
            (line_user_id,)
        ).fetchone()
        
        if not user:
            return jsonify({'success': False, 'message': '找不到該使用者'})
            
        return jsonify({
            'success': True,
            'user': {
                'line_user_id': user['line_user_id'],
                'google_email': user['google_email'],
                'is_authorized': bool(user['google_credentials']),
                'created_at': user['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            }
        })
    except Exception as e:
        logger.error(f"查詢使用者時發生錯誤: {str(e)}")
        return jsonify({'success': False, 'message': '查詢使用者時發生錯誤'})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))