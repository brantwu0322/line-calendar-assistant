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
LINE_CHANNEL_ACCESS_TOKEN=你的LINE頻道存取權杖
LINE_CHANNEL_SECRET=你的LINE頻道密鑰
GOOGLE_CALENDAR_ID=你的Google行事曆ID
GOOGLE_CALENDAR_CREDENTIALS=你的Google Calendar API憑證
GOOGLE_CALENDAR_TOKEN=你的Google Calendar API權杖
OPENAI_API_KEY=你的OpenAI API金鑰
```

3. 啟動應用程式：
```bash
python app.py
```

## 使用方式

### 文字訊息
1. 直接輸入行程描述，例如：
   - 明天下午兩點跟客戶開會
   - 下週三早上九點去看牙醫
   - 每週五下午三點做瑜珈
   - 三天後下午四點半打籃球

2. 系統會自動解析時間和事件內容，並建立相應的行程。

### 語音訊息（開發中）
1. 發送語音訊息描述行程
2. 系統會將語音轉換為文字
3. 解析文字內容並建立行程

## 注意事項

- 請確保環境變數正確設定
- 需要有效的 Google Calendar API 憑證
- 需要有效的 OpenAI API 金鑰
- 建議在安靜的環境中使用語音功能

## 開發進度

### 已完成
- [x] 基本文字訊息處理
- [x] Google Calendar 整合
- [x] 錯誤處理機制
- [x] 系統監控功能

### 開發中
- [ ] 語音訊息處理優化
- [ ] 行事曆查詢功能
- [ ] 行事曆管理功能
- [ ] 使用者體驗優化

## 貢獻指南

歡迎提交 Issue 和 Pull Request 來協助改進這個專案。

## 授權

MIT License 