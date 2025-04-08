import os
import json
import logging
import openai
from openai import OpenAI
from datetime import datetime, timedelta
from flask import Flask, request, abort
from linebot import LineBotApi, WebhookHandler
from linebot.exceptions import InvalidSignatureError
from linebot.models import MessageEvent, TextMessage, TextSendMessage
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
import mysql.connector
from mysql.connector import Error

# 載入環境變數
load_dotenv()

# 設定日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 初始化 LINE Bot
line_bot_api = LineBotApi(os.getenv('LINE_CHANNEL_ACCESS_TOKEN'))
handler = WebhookHandler(os.getenv('LINE_CHANNEL_SECRET'))

# 初始化 OpenAI
openai.api_key = os.getenv('OPENAI_API_KEY')
openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# 初始化 Flask 應用
app = Flask(__name__)

# 設定時區
tz = pytz.timezone('Asia/Taipei')

# 初始化資料庫連接
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME')
        )
        return connection
    except Error as e:
        logger.error(f"資料庫連接錯誤: {e}")
        return None

# 檢查並更新 Google 授權
def check_and_refresh_google_credentials(user_id):
    connection = get_db_connection()
    if not connection:
        return None

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT google_credentials FROM users WHERE line_user_id = %s", (user_id,))
        result = cursor.fetchone()
        
        if not result or not result['google_credentials']:
            return None

        credentials = pickle.loads(result['google_credentials'])
        
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            cursor.execute(
                "UPDATE users SET google_credentials = %s WHERE line_user_id = %s",
                (pickle.dumps(credentials), user_id)
            )
            connection.commit()
        
        return credentials
    except Exception as e:
        logger.error(f"更新 Google 授權時發生錯誤: {e}")
        return None
    finally:
        if connection:
            connection.close()

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
        # 建立授權流程
        flow = InstalledAppFlow.from_client_secrets_file(
            'credentials.json',
            ['https://www.googleapis.com/auth/calendar']
        )
        flow.redirect_uri = 'https://line-calendar-assistant.onrender.com/oauth2callback'
        
        # 產生授權 URL
        auth_url, _ = flow.authorization_url(prompt='consent')
        
        # 儲存授權狀態
        connection = get_db_connection()
        if connection:
            try:
                cursor = connection.cursor()
                cursor.execute(
                    "INSERT INTO users (line_user_id, auth_state) VALUES (%s, %s) ON DUPLICATE KEY UPDATE auth_state = %s",
                    (user_id, flow.state, flow.state)
                )
                connection.commit()
            finally:
                connection.close()
        
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
        connection = get_db_connection()
        if not connection:
            return "授權失敗：無法連接資料庫"
        
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT line_user_id FROM users WHERE auth_state = %s", (state,))
            result = cursor.fetchone()
            
            if not result:
                return "授權失敗：找不到對應的用戶"
            
            user_id = result['line_user_id']
            
            # 建立授權流程
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json',
                ['https://www.googleapis.com/auth/calendar']
            )
            flow.redirect_uri = 'https://line-calendar-assistant.onrender.com/oauth2callback'
            
            # 取得憑證
            flow.fetch_token(code=code)
            credentials = flow.credentials
            
            # 儲存憑證
            cursor.execute(
                "UPDATE users SET google_credentials = %s, auth_state = NULL WHERE line_user_id = %s",
                (pickle.dumps(credentials), user_id)
            )
            connection.commit()
            
            # 通知用戶
            line_bot_api.push_message(
                user_id,
                TextSendMessage(text="Google 日曆授權成功！")
            )
            
            return "授權成功！您可以關閉此視窗。"
        finally:
            connection.close()
    except Exception as e:
        logger.error(f"處理授權回調時發生錯誤: {e}")
        return "授權失敗，請稍後再試"

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

@handler.add(MessageEvent, message=TextMessage)
def handle_message(event):
    try:
        # 取得用戶 ID
        user_id = event.source.user_id
        
        # 取得訊息內容
        text = event.message.text
        
        # 檢查是否需要授權
        if text == '授權':
            if not is_authorized(user_id):
                # 建立授權 URL
                auth_url = create_authorization_url(user_id)
                # 回傳授權 URL 給用戶
                line_bot_api.reply_message(
                    event.reply_token,
                    TextSendMessage(text=f'請點擊以下連結進行授權：\n{auth_url}')
                )
            else:
                # 如果已經授權，提示用戶
                line_bot_api.reply_message(
                    event.reply_token,
                    TextSendMessage(text='您已經完成授權，不需要再次授權。')
                )
            return
        
        # 處理查詢行程
        if any(keyword in text for keyword in ['查詢行程', '查看行程', '我的行程']) or '的行程' in text:
            response = handle_event_query(user_id, text)
            line_bot_api.reply_message(
                event.reply_token,
                TextSendMessage(text=response)
            )
            return
        
        # 處理修改行程
        if any(keyword in text for keyword in ['修改行程', '更改行程', '更新行程']):
            response = handle_event_modification(user_id, text)
            line_bot_api.reply_message(
                event.reply_token,
                TextSendMessage(text=response)
            )
            return
        
        # 處理刪除行程
        if any(keyword in text for keyword in ['刪除行程', '移除行程', '取消行程']):
            response = handle_event_deletion(user_id, text)
            line_bot_api.reply_message(
                event.reply_token,
                TextSendMessage(text=response)
            )
            return
        
        # 處理新增行程
        if any(keyword in text for keyword in ['新增行程', '加入行程', '建立行程']):
            response = handle_event_addition(user_id, text)
            line_bot_api.reply_message(
                event.reply_token,
                TextSendMessage(text=response)
            )
            return
        
        # 處理取消授權
        if any(keyword in text for keyword in ['取消授權', '解除綁定', '斷開連結']):
            connection = get_db_connection()
            if connection:
                try:
                    cursor = connection.cursor()
                    cursor.execute(
                        "UPDATE users SET google_credentials = NULL WHERE line_user_id = %s",
                        (user_id,)
                    )
                    connection.commit()
                    line_bot_api.reply_message(
                        event.reply_token,
                        TextSendMessage(text="已取消 Google 日曆授權")
                    )
                finally:
                    connection.close()
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
                event.reply_token,
                TextSendMessage(text=help_text)
            )
            return
        
        # 預設回應
        line_bot_api.reply_message(
            event.reply_token,
            TextSendMessage(text="請輸入「幫助」查看使用說明")
        )
    except Exception as e:
        logger.error(f"處理訊息時發生錯誤: {e}")
        line_bot_api.reply_message(
            event.reply_token,
            TextSendMessage(text="處理訊息時發生錯誤，請稍後再試")
        )

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))