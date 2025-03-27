FROM python:3.11.8

WORKDIR /app

# 複製依賴文件
COPY requirements.txt .

# 安裝基本依賴
RUN pip install --no-cache-dir flask>=2.0.0 Werkzeug>=2.0.0 gunicorn>=20.0.0

# 安裝 LINE Bot SDK
RUN pip install --no-cache-dir line-bot-sdk>=3.0.0

# 安裝 Google API 相關依賴
RUN pip install --no-cache-dir \
    google-auth-oauthlib>=1.0.0 \
    google-auth-httplib2>=0.1.0 \
    google-api-python-client>=2.0.0

# 安裝其他依賴
RUN pip install --no-cache-dir \
    openai>=1.0.0 \
    python-dotenv>=0.19.0 \
    requests>=2.25.0

# 複製應用程式代碼
COPY . .

# 設定環境變數
ENV PORT=5000

# 暴露端口
EXPOSE 5000

# 啟動命令
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"] 