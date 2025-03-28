FROM python:3.9-slim

WORKDIR /app

# 安裝系統依賴
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# 安裝 Python 套件
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 複製應用程式檔案
COPY . .

# 設定環境變數
ENV PORT=5000
ENV PYTHONUNBUFFERED=1

# 啟動命令
CMD ["python", "app.py"] 