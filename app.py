import os
import logging
import sys
import time
from datetime import datetime, timedelta, time as datetime_time
import re
from flask import Flask, request, abort, redirect, url_for, session
from linebot.v3 import WebhookHandler
from linebot.v3.exceptions import InvalidSignatureError
from linebot.v3.webhooks import (
    MessageEvent,
    TextMessageContent,
    AudioMessageContent
)
from linebot.v3.messaging import Configuration, MessagingApi, ApiClient
from linebot.v3.messaging.models import (
    TextMessage,
    ReplyMessageRequest,
    AudioMessage
)
from linebot.v3.webhooks.models import MessageContent
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
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

# 設定日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 載入環境變數
load_dotenv()

# 設定資料庫路徑
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.db')
logger.info(f"Database path: {DB_PATH}")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'your-secret-key')
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# LINE Bot 設定
channel_access_token = os.getenv('LINE_CHANNEL_ACCESS_TOKEN')
channel_secret = os.getenv('LINE_CHANNEL_SECRET')

configuration = Configuration(access_token=channel_access_token)
api_client = ApiClient(configuration)
messaging_api = MessagingApi(api_client)
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
        service, error = get_google_calendar_service(line_user_id)
        
        if error:
            # 如果未授權，提供授權連結
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

# 初始化資料庫
def init_db():
    try:
        # 確保資料庫目錄存在
        db_dir = os.path.dirname(DB_PATH)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
            logger.info(f"Created database directory: {db_dir}")
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (line_user_id TEXT PRIMARY KEY, credentials TEXT)''')
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        raise

# 獲取用戶認證
def get_user_credentials(line_user_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT credentials FROM users WHERE line_user_id = ?', (line_user_id,))
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
        c.execute('INSERT OR REPLACE INTO users (line_user_id, credentials) VALUES (?, ?)',
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

def get_google_calendar_service(line_user_id):
    """取得使用者的 Google Calendar 服務"""
    creds = get_user_credentials(line_user_id)
    
    if not creds:
        return None, "請先完成 Google Calendar 授權"
    
    try:
        credentials = Credentials.from_authorized_user_info(creds)
        
        # 如果認證已過期，重新整理
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            save_user_credentials(line_user_id, {
                'token': credentials.token,
                'refresh_token': credentials.refresh_token,
                'token_uri': credentials.token_uri,
                'client_id': credentials.client_id,
                'client_secret': credentials.client_secret,
                'scopes': credentials.scopes
            })
        
        service = build('calendar', 'v3', credentials=credentials)
        return service, None
    except Exception as e:
        logging.error(f"取得 Google Calendar 服務時發生錯誤：{str(e)}")
        return None, "Google Calendar 服務發生錯誤"

# 在應用程式啟動時設置保活機制
@app.before_first_request
def setup_keep_alive():
    """設置保活機制"""
    import threading
    import time
    
    def keep_alive_loop():
        while True:
            keep_alive()
            time.sleep(1800)  # 每30分鐘執行一次
    
    thread = threading.Thread(target=keep_alive_loop, daemon=True)
    thread.start()
    logger.info("已啟動 LINE API 保活機制")

# OpenAI API 設定
openai.api_key = os.getenv('OPENAI_API_KEY')

# Google Calendar API 設定
SCOPES = ['https://www.googleapis.com/auth/calendar']
CALENDAR_ID = os.getenv('GOOGLE_CALENDAR_ID')

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
        
        logger.info(f"準備建立事件：{json.dumps(event_data, ensure_ascii=False)}")
        logger.info(f"使用的行事曆 ID：{CALENDAR_ID}")
        
        event = service.events().insert(calendarId=CALENDAR_ID, body=event_data).execute()
        logger.info(f"成功建立事件: {event.get('htmlLink')}")
        return True, event.get('htmlLink')
    except Exception as e:
        logger.error(f"建立事件時發生錯誤: {str(e)}")
        logger.exception("詳細錯誤資訊：")
        return False, str(e)

@app.route("/callback", methods=['POST'])
def callback():
    try:
        signature = request.headers['X-Line-Signature']
        body = request.get_data(as_text=True)
        logging.info(f"收到 LINE 訊息: {body}")
    
        try:
            handler.handle(body, signature)
        except Exception as e:
            logging.error(f"處理訊息時發生錯誤: {str(e)}")
            logging.error(f"錯誤類型: {type(e).__name__}")
            logging.error(f"錯誤詳情: {traceback.format_exc()}")
            return 'Error', 500
            
        return 'OK'
    except Exception as e:
        logging.error(f"回調處理時發生錯誤: {str(e)}")
        logging.error(f"錯誤類型: {type(e).__name__}")
        logging.error(f"錯誤詳情: {traceback.format_exc()}")
        return 'Error', 500

@handler.add(MessageEvent, message=TextMessageContent)
@require_authorization
def handle_text_message(event, service):
    """處理文字訊息"""
    text = event.message.text
    logging.info(f"收到文字訊息：{text}")
    
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
        logging.info("收到一般訊息，使用 GPT-4 處理")
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
    flow = InstalledAppFlow.from_client_secrets_file(
        'credentials.json',
        ['https://www.googleapis.com/auth/calendar']
    )
    flow.redirect_uri = url_for('oauth2callback', line_user_id=line_user_id, _external=True)
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback/<line_user_id>')
def oauth2callback(line_user_id):
    """處理 OAuth2 回調"""
    state = session['state']
    flow = InstalledAppFlow.from_client_secrets_file(
        'credentials.json',
        ['https://www.googleapis.com/auth/calendar'],
        state=state
    )
    flow.redirect_uri = url_for('oauth2callback', line_user_id=line_user_id, _external=True)
    
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    
    # 儲存認證資訊
    save_user_credentials(line_user_id, credentials)
    
    return "授權成功！請回到 LINE 繼續使用。"

if __name__ == "__main__":
    logger.info("Starting Flask application...")
    logger.info(f"LINE_CHANNEL_ACCESS_TOKEN: {os.getenv('LINE_CHANNEL_ACCESS_TOKEN')[:10]}...")
    logger.info(f"LINE_CHANNEL_SECRET: {os.getenv('LINE_CHANNEL_SECRET')[:10]}...")
    logger.info(f"GOOGLE_CALENDAR_ID: {os.getenv('GOOGLE_CALENDAR_ID')}")
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port) 