# LINE 行事曆助手

這是一個基於 LINE Messaging API 和 Google Calendar API 開發的聊天機器人，可以幫助用戶管理他們的行程。

## 功能特點

### 已實現功能
- [x] 文字訊息處理
  - [x] 支援自然語言輸入
  - [x] 支援中文時間表達
  - [x] 支援循環事件設定
  - [x] 支援一般對話回應
- [x] Google Calendar 整合
  - [x] 自動建立行程
  - [x] 支援循環事件
  - [x] 時區處理
- [x] 錯誤處理
  - [x] 詳細的錯誤日誌
  - [x] 友善的錯誤提示
  - [x] 自動重試機制
- [x] 系統監控
  - [x] 詳細的日誌記錄
  - [x] LINE API 保活機制

### 開發中功能
- [ ] 語音訊息處理
  - [ ] 語音轉文字
  - [ ] 音訊格式轉換
  - [ ] 噪音處理
- [ ] 行事曆查詢
  - [ ] 查詢特定日期行程
  - [ ] 查詢未來行程
  - [ ] 行程提醒功能
- [ ] 行事曆管理
  - [ ] 修改行程
  - [ ] 刪除行程
  - [ ] 行程衝突檢查
- [ ] 使用者體驗優化
  - [ ] 快速回覆按鈕
  - [ ] 行程卡片預覽
  - [ ] 多語言支援

## 技術架構

- 後端框架：Flask
- 聊天平台：LINE Messaging API
- 行事曆服務：Google Calendar API
- 自然語言處理：OpenAI GPT-4
- 語音處理：SpeechRecognition, pydub
- 部署平台：Render

## 環境設定

1. 安裝依賴套件：
```bash
pip install -r requirements.txt
```

2. 設定環境變數：
```bash
LINE_CHANNEL_ACCESS_TOKEN=你的LINE Channel Access Token
LINE_CHANNEL_SECRET=你的LINE Channel Secret
GOOGLE_CALENDAR_CREDENTIALS=你的Google Calendar API憑證
GOOGLE_CALENDAR_TOKEN=你的Google Calendar API權杖
OPENAI_API_KEY=你的OpenAI API金鑰
FLASK_SECRET_KEY=你的Flask密鑰
```

3. 啟動應用程式：
```bash
python app.py
```