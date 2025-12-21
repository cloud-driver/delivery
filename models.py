from datetime import datetime
from flask_login import UserMixin 
from extensions import db

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=True)
    password_hash = db.Column(db.String(200), nullable=True)
    
    line_user_id = db.Column(db.String(128), unique=True, nullable=True)
    google_user_id = db.Column(db.String(128), unique=True, nullable=True)
    email = db.Column(db.String(128), unique=True, nullable=True) 
    display_name = db.Column(db.String(128), nullable=True)

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.DateTime, default=datetime.now)
    content = db.Column(db.String(500), nullable=False)

class OAuthState(db.Model):
    __tablename__ = 'oauth_states'
    id = db.Column(db.Integer, primary_key=True)
    state_token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    flow_type = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

class Video(db.Model):
    __tablename__ = 'videos'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False) # 儲存檔名
    url = db.Column(db.String(255), nullable=False)      # 儲存連結路徑
    title = db.Column(db.String(255), nullable=True)     # 可選：影片標題
    uploader_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True) # 連結到上傳者
    created_at = db.Column(db.DateTime, default=datetime.now)

    # 建立關聯，方便查詢評論與按讚
    comments = db.relationship('Comment', backref='video', lazy=True, cascade="all, delete-orphan")
    likes = db.relationship('VideoLike', backref='video', lazy=True, cascade="all, delete-orphan")

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # 關聯：哪個用戶在哪個影片留言
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    video_id = db.Column(db.Integer, db.ForeignKey('videos.id'), nullable=False)
    
    # 方便直接取得用戶物件
    user = db.relationship('User', backref='comments')

class VideoLike(db.Model):
    __tablename__ = 'video_likes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    video_id = db.Column(db.Integer, db.ForeignKey('videos.id'), nullable=False)
    
    # 確保一個用戶對一部影片只能按一次讚
    __table_args__ = (db.UniqueConstraint('user_id', 'video_id', name='unique_user_video_like'),)