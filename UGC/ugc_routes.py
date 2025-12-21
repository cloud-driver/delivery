import os
from flask import Blueprint, request, jsonify, current_app, url_for
from werkzeug.utils import secure_filename
from extensions import db
from models import Video, Comment, VideoLike, User
from utils import token_required, save_log_to_db

ugc_bp = Blueprint('ugc_bp', __name__)

ALLOWED_EXTENSIONS = {'mp4', 'mov', 'avi'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@ugc_bp.route("/upload", methods=["POST"])
@token_required
def upload_video(current_user: User):
    """上傳影片 API (需登入)"""
    file = request.files.get("file")
    if not file or file.filename == '':
        return jsonify({"error": "未選擇檔案"}), 400
    
    if not allowed_file(file.filename):
        return jsonify({"error": "檔案格式錯誤，僅支援 mp4, mov, avi"}), 400

    filename = secure_filename(file.filename)
    
    # 確保上傳目錄存在 (從 config 讀取路徑)
    upload_folder = current_app.config.get('UPLOAD_FOLDER', 'static/video')
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)
        
    filepath = os.path.join(upload_folder, filename)
    
    # 避免檔名重複覆蓋，實務上通常會加時間戳記或 UUID，這裡簡化處理
    if os.path.exists(filepath):
        base, ext = os.path.splitext(filename)
        import uuid
        filename = f"{base}_{uuid.uuid4().hex[:8]}{ext}"
        filepath = os.path.join(upload_folder, filename)

    try:
        file.save(filepath)
        
        # 存入資料庫
        # 注意：url 需對應前端可存取的靜態路徑
        video_url = f"/static/video/{filename}" 
        new_video = Video(
            filename=filename,
            url=video_url,
            uploader_id=current_user.id,
            title=request.form.get('title', filename)
        )
        db.session.add(new_video)
        db.session.commit()
        
        save_log_to_db(f"用戶 {current_user.username} 上傳了影片: {filename}")
        
        return jsonify({
            "message": "影片上傳成功", 
            "video_id": new_video.id,
            "video_url": new_video.url
        }), 201
        
    except Exception as e:
        save_log_to_db(f"上傳失敗: {str(e)}")
        return jsonify({"error": "伺服器儲存失敗"}), 500

@ugc_bp.route("/<int:video_id>/comments", methods=["GET"])
def get_comments(video_id):
    """取得影片評論 (公開 API)"""
    video = Video.query.get(video_id)
    if not video:
        return jsonify({"error": "影片不存在"}), 404
    
    # 透過關聯查詢該影片的所有評論
    result = []
    for c in video.comments:
        result.append({
            "id": c.id,
            "user": c.user.username if c.user else "未知用戶",
            "content": c.content,
            "created_at": c.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
        
    return jsonify({
        "video_id": video_id, 
        "comments": result
    })

@ugc_bp.route("/<int:video_id>/comments", methods=["POST"])
@token_required
def add_comment(current_user: User, video_id):
    """新增評論 (需登入)"""
    video = Video.query.get(video_id)
    if not video:
        return jsonify({"error": "影片不存在"}), 404
        
    data = request.get_json()
    content = data.get("content")
    
    if not content:
        return jsonify({"error": "評論內容不可為空"}), 400
    
    try:
        new_comment = Comment(
            content=content,
            user_id=current_user.id,
            video_id=video.id
        )
        db.session.add(new_comment)
        db.session.commit()
        return jsonify({"message": "評論新增成功", "user": current_user.username})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "新增失敗"}), 500

@ugc_bp.route("/<int:video_id>/like", methods=["POST"])
@token_required
def toggle_like(current_user: User, video_id):
    """切換按讚/取消讚 (需登入)"""
    video = Video.query.get(video_id)
    if not video:
        return jsonify({"error": "影片不存在"}), 404
        
    existing_like = VideoLike.query.filter_by(user_id=current_user.id, video_id=video_id).first()
    
    try:
        if existing_like:
            db.session.delete(existing_like)
            message = "已取消讚"
            is_liked = False
        else:
            new_like = VideoLike(user_id=current_user.id, video_id=video_id)
            db.session.add(new_like)
            message = "已按讚"
            is_liked = True
            
        db.session.commit()
        
        # 計算總讚數
        total_likes = VideoLike.query.filter_by(video_id=video_id).count()
        
        return jsonify({
            "message": message, 
            "is_liked": is_liked,
            "likes_count": total_likes
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "操作失敗"}), 500

@ugc_bp.route("/list", methods=["GET"])
def list_videos():
    """列出所有影片"""
    videos = Video.query.order_by(Video.created_at.desc()).all()
    output = []
    for v in videos:
        output.append({
            "id": v.id,
            "title": v.title,
            "url": v.url,
            "uploader": v.uploader_id, # 或者 query uploader 的名字
            "likes_count": len(v.likes),
            "comments_count": len(v.comments)
        })
    return jsonify(output)