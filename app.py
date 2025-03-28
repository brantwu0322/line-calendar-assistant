import os
import logging
import sys
from datetime import datetime, timedelta, time
import re
from flask import Flask, request, abort
from linebot.v3 import WebhookHandler
from linebot.v3.exceptions import InvalidSignatureError
from linebot.v3.webhooks import (
    MessageEvent,
    TextMessageContent,
    AudioMessageContent
)
from linebot.v3.messaging import Configuration
from linebot.v3.messaging.models import (
    TextMessage,
    ReplyMessageRequest,
    AudioMessage
)
from linebot.v3.webhooks.models import MessageContent
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import speech_recognition as sr
import tempfile
import json
from linebot.v3.messaging.api import MessagingApi
from linebot.v3.messaging.api_client import ApiClient
import openai
import requests

# 設定日誌
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('app.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# 移除重複的日誌處理器
for handler in logging.getLogger().handlers[:]:
    logging.getLogger().removeHandler(handler)

app = Flask(__name__)

# LINE Bot 設定
configuration = Configuration(access_token=os.getenv('LINE_CHANNEL_ACCESS_TOKEN'))
api_client = ApiClient(configuration)
messaging_api = MessagingApi(api_client)
handler = WebhookHandler(os.getenv('LINE_CHANNEL_SECRET'))

# OpenAI API 設定
openai.api_key = os.getenv('OPENAI_API_KEY')

# Google Calendar API 設定
SCOPES = ['https://www.googleapis.com/auth/calendar']
CALENDAR_ID = os.getenv('GOOGLE_CALENDAR_ID')

def get_google_calendar_service():
    """取得 Google Calendar API 服務"""
    creds = None
    
    # 從環境變數獲取憑證
    if os.getenv('GOOGLE_CALENDAR_CREDENTIALS') and os.getenv('GOOGLE_CALENDAR_TOKEN'):
        # 從環境變數讀取憑證
        creds_info = json.loads(os.getenv('GOOGLE_CALENDAR_CREDENTIALS'))
        token_info = json.loads(os.getenv('GOOGLE_CALENDAR_TOKEN'))
        
        creds = Credentials.from_authorized_user_info(token_info, SCOPES)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
                # 更新環境變數中的 token
                os.environ['GOOGLE_CALENDAR_TOKEN'] = json.dumps(json.loads(creds.to_json()))
    else:
        # 如果環境變數中沒有憑證，嘗試從文件讀取
        if os.path.exists('token.json'):
            creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            
            # 保存到文件
            with open('token.json', 'w') as token:
                token.write(creds.to_json())
    
    return build('calendar', 'v3', credentials=creds)

def parse_event_text(text):
    """解析文字中的行程資訊"""
    logger.info(f"開始解析文字：{text}")
    
    try:
        # 使用 GPT-4 進行語意分析
        client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        response = client.chat.completions.create(
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
                    1. is_recurring 只有在輸入明確包含「每週」、「每個禮拜」或「連續X個週Y」等循環描述時才設為 true
                    2. recurrence_count 只有在 is_recurring 為 true 時才設定數值，預設為 null
                    3. 一般的單次行程（如：明天下午三點開會）應該將 is_recurring 設為 false
                    
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
        
        parsed_data = json.loads(response.choices[0].message.content)
        logger.info(f"GPT 解析結果：{json.dumps(parsed_data, ensure_ascii=False)}")
        
        if not parsed_data:
            logger.info("GPT 無法解析文字")
            return None
            
        # 取得當前時間
        now = datetime.now()
        today = now.date()
        
        # 解析日期
        date_str = parsed_data.get('date_type')
        if not date_str:
            return None
            
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
            days_ahead = (target_weekday - current_weekday + 7) % 7
            target_date = today + timedelta(days=days_ahead)
        elif date_str.startswith('下下週'):
            weekday_map = {'一': 0, '二': 1, '三': 2, '四': 3, '五': 4, '六': 5, '日': 6}
            target_weekday = weekday_map[date_str[3]]
            current_weekday = today.weekday()
            days_ahead = (target_weekday - current_weekday + 14) % 14
            target_date = today + timedelta(days=days_ahead)
        elif date_str.startswith('連續'):
            weekday_str = date_str.split('週')[1]
            weekday_map = {'一': 0, '二': 1, '三': 2, '四': 3, '五': 4, '六': 5, '日': 6}
            target_weekday = weekday_map[weekday_str]
            current_weekday = today.weekday()
            days_ahead = (target_weekday - current_weekday + 7) % 7
            target_date = today + timedelta(days=days_ahead)
        else:
            logger.info(f"無法解析的日期格式：{date_str}")
            return None
        
        # 設定時間
        hour = int(parsed_data.get('hour', 0))
        minute = int(parsed_data.get('minute', 0))
        time_period = parsed_data.get('time_period')
        
        # 處理上午/下午
        if time_period == '下午' and hour < 12:
            hour += 12
        elif time_period == '上午' and hour == 12:
            hour = 0
        
        start_time = datetime.combine(target_date, time(hour, minute))
        end_time = start_time + timedelta(hours=1)
        
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

def create_calendar_event(event_data):
    """建立 Google Calendar 事件"""
    try:
        service = get_google_calendar_service()
        
        event = {
            'summary': event_data['summary'],
            'start': event_data['start'],
            'end': event_data['end']
        }
        
        if 'recurrence' in event_data:
            event['recurrence'] = event_data['recurrence']
        
        event = service.events().insert(calendarId=CALENDAR_ID, body=event).execute()
        logger.info(f"成功建立事件: {event.get('htmlLink')}")
        return True, event.get('htmlLink')
    except Exception as e:
        logger.error(f"建立事件時發生錯誤: {str(e)}")
        return False, str(e)

@app.route("/callback", methods=['POST'])
def callback():
    """處理 LINE 訊息"""
    logger.info("收到 LINE 回調請求")
    try:
        signature = request.headers['X-Line-Signature']
        body = request.get_data(as_text=True)
        logger.debug(f"請求內容: {body}")
        logger.debug(f"簽章: {signature}")
        
        try:
            handler.handle(body, signature)
            logger.info("成功處理 LINE 回調請求")
        except InvalidSignatureError as e:
            logger.error(f"無效的簽章: {str(e)}")
            abort(400)
        except Exception as e:
            logger.error(f"處理回調請求時發生錯誤: {str(e)}")
            logger.exception("詳細錯誤資訊：")
            abort(500)
        
        return 'OK'
    except Exception as e:
        logger.error(f"處理請求時發生錯誤: {str(e)}")
        logger.exception("詳細錯誤資訊：")
        abort(500)

@handler.add(MessageEvent, message=TextMessageContent)
def handle_message(event):
    """處理文字訊息"""
    logger.info(f"收到文字訊息: {event.message.text}")
    logger.debug(f"事件詳情: {event}")
    
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            if event.message.text.lower() == "測試":
                reply_text = "收到測試訊息！LINE Bot 正常運作中。"
            else:
                event_data = parse_event_text(event.message.text)
                if event_data:
                    success, result = create_calendar_event(event_data)
                    if success:
                        reply_text = f"已成功建立行程：{event_data['summary']}\n{result}"
                    else:
                        reply_text = f"建立行程失敗：{result}"
                else:
                    reply_text = "無法解析行程資訊。您可以這樣說：\n- 明天下午兩點跟客戶開會\n- 下週三早上九點去看牙醫\n- 每週五下午三點做瑜珈\n- 三天後下午四點半打籃球\n- 連續四個禮拜的週一早上九點開會"
            
            logger.info(f"準備回覆訊息: {reply_text}")
            try:
                messaging_api.reply_message(
                    ReplyMessageRequest(
                        reply_token=event.reply_token,
                        messages=[TextMessage(text=reply_text)]
                    )
                )
                logger.info("成功發送回覆訊息")
                break  # 成功發送後跳出重試循環
            except Exception as e:
                logger.error(f"發送回覆訊息時發生錯誤: {str(e)}")
                logger.exception("詳細錯誤資訊：")
                retry_count += 1
                if retry_count >= max_retries:
                    raise
                continue
        except Exception as e:
            logger.error(f"處理訊息時發生錯誤: {str(e)}")
            logger.exception("詳細錯誤資訊：")
            retry_count += 1
            if retry_count >= max_retries:
                try:
                    messaging_api.reply_message(
                        ReplyMessageRequest(
                            reply_token=event.reply_token,
                            messages=[TextMessage(text=f"處理訊息時發生錯誤，請稍後再試。")]
                        )
                    )
                except Exception as reply_error:
                    logger.error(f"發送錯誤訊息時也發生錯誤: {str(reply_error)}")
                    logger.exception("詳細錯誤資訊：")
                break

@handler.add(MessageEvent, message=AudioMessageContent)
def handle_audio_message(event):
    """處理語音訊息"""
    logger.info("收到語音訊息")
    try:
        # 獲取語音訊息內容
        headers = {
            'Authorization': f'Bearer {os.getenv("LINE_CHANNEL_ACCESS_TOKEN")}'
        }
        response = requests.get(
            f"https://api-data.line.me/v2/bot/message/{event.message.id}/content",
            headers=headers
        )
        audio_content = response.content
        
        # 儲存語音檔案
        with tempfile.NamedTemporaryFile(delete=False, suffix='.m4a') as temp_file:
            temp_file.write(audio_content)
            temp_file_path = temp_file.name
        
        # 使用 Whisper API 轉換語音為文字
        with open(temp_file_path, 'rb') as audio_file:
            client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
            transcript = client.audio.transcriptions.create(
                model="whisper-1",
                file=audio_file
            )
            text = transcript.text
        
        # 刪除暫存檔案
        os.unlink(temp_file_path)
        
        logger.info(f"語音識別結果：{text}")
        
        # 使用 GPT-4 來解析和格式化文字
        client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {
                    "role": "system",
                    "content": "你是一個行程解析助手。請將用戶的語音文字轉換成標準格式的行程描述。例如：'今天下午2點開會'、'明天上午9點開會'。"
                },
                {
                    "role": "user",
                    "content": text
                }
            ],
            max_tokens=100
        )
        
        formatted_text = response.choices[0].message.content.strip()
        logger.info(f"格式化後的文字：{formatted_text}")
        
        # 解析文字並建立行程
        event_data = parse_event_text(formatted_text)
        if event_data:
            success, result = create_calendar_event(event_data)
            if success:
                reply_text = f"已成功建立行程：{event_data['summary']}\n{result}"
            else:
                reply_text = f"建立行程失敗：{result}"
        else:
            reply_text = "無法解析語音內容中的行程資訊，請使用正確的格式，例如：\n明天下午2點開會\n下週一上午9點開會"
        
        messaging_api.reply_message(
            ReplyMessageRequest(
                reply_token=event.reply_token,
                messages=[TextMessage(text=reply_text)]
            )
        )
    except Exception as e:
        logger.error(f"處理語音訊息時發生錯誤: {str(e)}")
        logger.exception("詳細錯誤資訊：")
        messaging_api.reply_message(
            ReplyMessageRequest(
                reply_token=event.reply_token,
                messages=[TextMessage(text=f"處理語音訊息時發生錯誤：{str(e)}")]
            )
        )

if __name__ == "__main__":
    logger.info("Starting Flask application...")
    logger.info(f"LINE_CHANNEL_ACCESS_TOKEN: {os.getenv('LINE_CHANNEL_ACCESS_TOKEN')[:10]}...")
    logger.info(f"LINE_CHANNEL_SECRET: {os.getenv('LINE_CHANNEL_SECRET')[:10]}...")
    logger.info(f"GOOGLE_CALENDAR_ID: {os.getenv('GOOGLE_CALENDAR_ID')}")
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)