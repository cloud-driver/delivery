#!/bin/bash

# 1. 啟動 Cloudflared 通道 (Sidecar)
# 這會把遠端的 db.hasaki.idv.tw 映射到 Container 內部的 localhost:3306
echo "Starting Cloudflared Tunnel..."
nohup cloudflared access tcp --hostname db.hasaki.idv.tw --url 127.0.0.1:3306 > cloudflared.log 2>&1 &

# 2. 等待幾秒鐘讓通道建立
echo "Waiting for Tunnel to establish..."
sleep 5

# 3. 啟動 Flask 應用程式
echo "Starting Flask Application..."
# 注意：這裡不要用 CMD [...] 的陣列寫法，直接寫指令
exec gunicorn -w 2 -b 0.0.0.0:$PORT --timeout 120 app:app