import os
import logging
import sys
import time
from datetime import datetime, timedelta, time as datetime_time
import re
from flask import Flask, request, abort
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
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import speech_recognition as sr
import tempfile
import json
import openai
import requests
import traceback

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
channel_access_token = os.getenv('LINE_CHANNEL_ACCESS_TOKEN')
channel_secret = os.getenv('LINE_CHANNEL_SECRET')

configuration = Configuration(
    access_token=channel_access_token
)
api_client = ApiClient(configuration)
handler = WebhookHandler(channel_secret)
messaging_api = MessagingApi(api_client)

# 添加保活機制
def keep_alive():
    """定期發送保活請求"""
    try:
        messaging_api.get_bot_info()
        logger.info("LINE API 保活成功")
    except Exception as e:
        logger.error(f"LINE API 保活失敗: {str(e)}")
        logger.exception("詳細錯誤資訊：")

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
                       - "明天" 指明天
                       - "後天" 指後天
                       - "大後天" 指大後天
                       - "下週X" 指下週的某一天
                       - "下下週X" 指下下週的某一天
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
            days_ahead = (target_weekday - current_weekday + 7) % 7
            target_date = today + timedelta(days=days_ahead)
        elif date_str.startswith('下下週'):
            weekday_map = {'一': 0, '二': 1, '三': 2, '四': 3, '五': 4, '六': 5, '日': 6}
            target_weekday = weekday_map[date_str[3]]
            current_weekday = today.weekday()
            days_ahead = (target_weekday - current_weekday + 14) % 14
            target_date = today + timedelta(days=days_ahead)
        elif date_str.startswith('連續'):
            # 解析連續週數
            count = int(date_str.split('個')[0].replace('連續', ''))
            weekday_str = date_str.split('週')[1]
            weekday_map = {'一': 0, '二': 1, '三': 2, '四': 3, '五': 4, '六': 5, '日': 6}
            target_weekday = weekday_map[weekday_str]
            current_weekday = today.weekday()
            days_ahead = (target_weekday - current_weekday + 7) % 7
            target_date = today + timedelta(days=days_ahead)
            parsed_data['recurrence_count'] = count
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
def handle_message(event):
    try:
        logging.info(f"開始處理訊息: {event.message.text}")
        retry_count = 0
        max_retries = 3
        
        while retry_count < max_retries:
            try:
                # 檢查是否為測試訊息
                if event.message.text.lower() == "測試":
                    logging.info("收到測試訊息")
                    messaging_api.reply_message(
                        ReplyMessageRequest(
                            reply_token=event.reply_token,
                            messages=[TextMessage(text="收到您的測試訊息！")]
                        )
                    )
                    return
                
                # 檢查是否為行程相關訊息
                if "行程" in event.message.text or "約會" in event.message.text or "開會" in event.message.text:
                    logging.info("開始處理行程訊息")
                    # 解析事件資訊
                    event_info = parse_event_text(event.message.text)
                    logging.info(f"解析結果: {event_info}")
                    
                    if event_info:
                        logging.info("成功解析事件資訊，開始建立事件")
                        # 建立事件
                        success, result = create_calendar_event(event_info)
                        if success:
                            logging.info(f"成功建立事件，結果: {result}")
                            messaging_api.reply_message(
                                ReplyMessageRequest(
                                    reply_token=event.reply_token,
                                    messages=[TextMessage(text=f"已成功建立行程：\n{event_info['summary']}\n時間：{event_info['start']['dateTime']} - {event_info['end']['dateTime']}")]
                                )
                            )
                        else:
                            logging.error("建立事件失敗")
                            messaging_api.reply_message(
                                ReplyMessageRequest(
                                    reply_token=event.reply_token,
                                    messages=[TextMessage(text="抱歉，建立行程時發生錯誤。")]
                                )
                            )
                    else:
                        logging.error("無法解析事件資訊")
                        messaging_api.reply_message(
                            ReplyMessageRequest(
                                reply_token=event.reply_token,
                                messages=[TextMessage(text="抱歉，我無法理解您的行程資訊。請使用以下格式：\n1. 明天下午兩點跟客戶開會\n2. 下週三早上九點去看牙醫\n3. 每週五下午三點做瑜珈\n4. 三天後下午四點半打籃球")]
                            )
                        )
                    break
                else:
                    logging.info("收到一般訊息，使用 GPT-4 處理")
                    # 使用 GPT-4 處理一般訊息
                    response = openai.ChatCompletion.create(
                        model="gpt-4",
                        messages=[
                            {"role": "system", "content": "你是一個友善的 LINE 聊天機器人助手，請用簡短、親切的語氣回答。"},
                            {"role": "user", "content": event.message.text}
                        ]
                    )
                    reply_text = response.choices[0].message.content
                    logging.info(f"GPT-4 回應: {reply_text}")
                    messaging_api.reply_message(
                        ReplyMessageRequest(
                            reply_token=event.reply_token,
                            messages=[TextMessage(text=reply_text)]
                        )
                    )
                    break
                    
            except Exception as e:
                retry_count += 1
                logging.error(f"處理訊息時發生錯誤 (嘗試 {retry_count}/{max_retries}): {str(e)}")
                logging.error(f"錯誤類型: {type(e).__name__}")
                logging.error(f"錯誤詳情: {traceback.format_exc()}")
                
                if retry_count == max_retries:
                    logging.error("達到最大重試次數")
                    messaging_api.reply_message(
                        ReplyMessageRequest(
                            reply_token=event.reply_token,
                            messages=[TextMessage(text="抱歉，處理您的訊息時發生錯誤，請稍後再試。")]
                        )
                    )
                else:
                    time.sleep(1)  # 等待一秒後重試
                    
    except Exception as e:
        logging.error(f"處理訊息時發生未預期的錯誤: {str(e)}")
        logging.error(f"錯誤類型: {type(e).__name__}")
        logging.error(f"錯誤詳情: {traceback.format_exc()}")
        messaging_api.reply_message(
            ReplyMessageRequest(
                reply_token=event.reply_token,
                messages=[TextMessage(text="抱歉，系統發生錯誤，請稍後再試。")]
            )
        )

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