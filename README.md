# LINE 行事曆助理

這是一個 LINE Bot 應用程式，可以幫助您輕鬆管理 Google 行事曆。您可以透過文字、語音或圖片的方式新增行程。

## 功能特點

- 支援文字訊息輸入行程
- 支援語音訊息輸入行程
- 支援圖片訊息（例如：會議通知截圖）
- 自動解析行程資訊
- 支援單次和重複性行程
- 與 Google Calendar 整合

## 安裝步驟

1. 安裝所需套件：
```bash
pip install -r requirements.txt
```

2. 設定環境變數：
   - 複製 `.env.example` 為 `.env`
   - 填入您的 LINE Channel Secret 和 Channel Access Token
   - 設定 Google Calendar API 認證資訊

3. 執行應用程式：
```bash
python app.py
```

## 環境變數設定

在 `.env` 檔案中需要設定以下變數：

- `LINE_CHANNEL_SECRET`: LINE Channel Secret
- `LINE_CHANNEL_ACCESS_TOKEN`: LINE Channel Access Token
- `GOOGLE_CALENDAR_CREDENTIALS`: Google Calendar API 認證資訊

## 使用方式

1. 將 LINE Bot 加入好友
2. 傳送文字訊息，例如：
   - "明天下午2點開會"
   - "每週一早上9點團隊會議"
3. 傳送語音訊息描述行程
4. 傳送會議通知截圖

## 部署說明

本應用程式可以部署在以下平台：
- Heroku
- Google Cloud Platform
- AWS
- Azure

## 注意事項

- 首次使用需要進行 Google Calendar 授權
- 語音訊息需要清晰的語音品質
- 圖片訊息需要清晰的文字內容 