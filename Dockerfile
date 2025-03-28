FROM python:3.11.8

WORKDIR /app

# 安裝基本工具
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 複製應用程式代碼
COPY . .

# 安裝依賴
RUN pip install flask==3.0.2
RUN pip install Werkzeug==3.0.1
RUN pip install gunicorn==21.2.0
RUN pip install line-bot-sdk==3.7.0
RUN pip install google-auth-oauthlib==1.2.0
RUN pip install google-auth-httplib2==0.2.0
RUN pip install google-api-python-client==2.120.0
RUN pip install openai==1.12.0
RUN pip install python-dotenv==1.0.1
RUN pip install requests==2.31.0

# 設定環境變數
ENV PORT=5000

# 暴露端口
EXPOSE 5000

# 啟動命令
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"] 