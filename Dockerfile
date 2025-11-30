# 使用輕量級的 Python 3.9
FROM python:3.9-slim

# 設定工作目錄
WORKDIR /app

# 安裝系統層級依賴：ffmpeg (這是關鍵) 和 git
RUN apt-get update && apt-get install -y \
    ffmpeg \
    git \
    && rm -rf /var/lib/apt/lists/*

# 複製並安裝 Python 套件
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 複製程式碼
COPY . .

# 啟動指令 (根據你的 requirements.txt，你用的是 gunicorn)
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:10000", "--timeout", "120", "app:app"]