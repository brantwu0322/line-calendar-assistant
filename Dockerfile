FROM python:3.11.8

WORKDIR /app

# 升級 pip 並安裝基本工具
RUN pip install --upgrade pip setuptools wheel

# 安裝基本依賴
RUN pip install \
    flask==3.0.2 \
    Werkzeug==3.0.1 \
    gunicorn==21.2.0

# 安裝 LINE Bot SDK
RUN pip install line-bot-sdk==3.7.0

# 安裝 Google API 相關依賴
RUN pip install \
    google-auth-oauthlib==1.2.0 \
    google-auth-httplib2==0.2.0 \
    google-api-python-client==2.120.0

# 安裝其他依賴
RUN pip install \
    openai==1.12.0 \
    python-dotenv==1.0.1 \
    requests==2.31.0

# 複製應用程式代碼
COPY . .

# 設定環境變數
ENV PORT=5000

# 暴露端口
EXPOSE 5000

# 啟動命令
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"] 