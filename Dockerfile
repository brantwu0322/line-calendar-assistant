FROM python:3.11.8-slim

WORKDIR /app

# 安裝基本系統依賴
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# 複製依賴文件
COPY requirements.txt .

# 安裝 Python 依賴（添加詳細日誌）
RUN pip install --no-cache-dir -r requirements.txt -v

# 複製應用程式代碼
COPY . .

# 設定環境變數
ENV PORT=5000

# 暴露端口
EXPOSE 5000

# 啟動命令
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"] 