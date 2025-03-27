FROM python:3.11.8-slim

WORKDIR /app

# 複製應用程式代碼
COPY . .

# 安裝依賴
RUN pip install --no-cache-dir flask==3.0.2 \
    Werkzeug==3.0.1 \
    gunicorn==21.2.0 \
    line-bot-sdk==3.7.0 \
    google-auth-oauthlib==1.2.0 \
    google-auth-httplib2==0.2.0 \
    google-api-python-client==2.120.0 \
    openai==1.12.0 \
    python-dotenv==1.0.1 \
    requests==2.31.0

# 設定環境變數
ENV PORT=5000

# 暴露端口
EXPOSE 5000

# 啟動命令
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"] 