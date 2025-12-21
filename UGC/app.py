from flask import Flask, request, jsonify
import os

app = Flask(__name__)

UPLOAD_FOLDER = os.path.join("static", "video")
DATA_FOLDER = "data"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATA_FOLDER, exist_ok=True)

VIDEOS = {}
COMMENTS_FILE = os.path.join(DATA_FOLDER, "comments.txt")
LIKES_FILE = os.path.join(DATA_FOLDER, "likes.txt")

# 影片上傳
@app.route("/api/videos/upload", methods=["POST"])
def upload_video():
    file = request.files.get("file")
    if not file or not file.filename.endswith(".mp4"):
        return jsonify({"error": "檔案格式錯誤，僅支援 mp4"}), 400
    
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    video_id = len(VIDEOS) + 1
    VIDEOS[video_id] = {
        "id": video_id,
        "filename": file.filename,
        "url": f"/static/video/{file.filename}"
    }
    return jsonify({"message": "影片上傳成功", "video_url": VIDEOS[video_id]["url"]})

# 取得評論
@app.route("/api/videos/<int:video_id>/comments", methods=["GET"])
def get_comments(video_id):
    if video_id not in VIDEOS:
        return jsonify({"error": "影片不存在"}), 404
    
    comments = []
    if os.path.exists(COMMENTS_FILE):
        with open(COMMENTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                vid, user, content = line.strip().split("|")
                if int(vid) == video_id:
                    comments.append({"user": user, "content": content})
    return jsonify({"video_id": video_id, "comments": comments})

# 新增評論
@app.route("/api/videos/<int:video_id>/comments", methods=["POST"])
def add_comment(video_id):
    if video_id not in VIDEOS:
        return jsonify({"error": "影片不存在"}), 404
    data = request.json
    if not data.get("content"):
        return jsonify({"error": "評論內容不可為空"}), 400
    
    with open(COMMENTS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{video_id}|測試用戶|{data['content']}\n")
    return jsonify({"message": "評論新增成功"})

# 切換按讚
@app.route("/api/videos/<int:video_id>/like", methods=["POST"])
def toggle_like(video_id):
    if video_id not in VIDEOS:
        return jsonify({"error": "影片不存在"}), 404
    
    user_id = "user1"  # 模擬使用者
    likes = set()
    if os.path.exists(LIKES_FILE):
        with open(LIKES_FILE, "r", encoding="utf-8") as f:
            likes = set(line.strip() for line in f if line.strip())
    
    if f"{video_id}|{user_id}" in likes:
        likes.remove(f"{video_id}|{user_id}")
        message = "已取消讚"
    else:
        likes.add(f"{video_id}|{user_id}")
        message = "已按讚"
    
    with open(LIKES_FILE, "w", encoding="utf-8") as f:
        for like in likes:
            f.write(like + "\n")
    
    return jsonify({"message": message, "likes_count": sum(1 for l in likes if l.startswith(str(video_id)))})

if __name__ == "__main__":
    app.run(debug=True)