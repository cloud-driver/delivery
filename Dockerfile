# 使用 Python 3.10
FROM python:3.10-slim

# 設定工作目錄
WORKDIR /app

# 1. 安裝系統工具：curl (下載用), git, ffmpeg
RUN apt-get update && apt-get install -y \
    curl \
    git \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# 2. 下載並安裝 Cloudflared (這是關鍵新增的步驟)
RUN curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb && \
    dpkg -i cloudflared.deb && \
    rm cloudflared.deb

# 3. 複製並安裝 Python 套件
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. 複製所有程式碼
COPY . .

# 5. 給予腳本執行權限 (重要！不然 Render 會跑不動)
RUN chmod +x entrypoint.sh

# 6. 啟動指令改為執行 entrypoint.sh (原本是直接執行 gunicorn)
CMD ["./entrypoint.sh"]