import jwt
import random
import string
import secrets
import hashlib
import base64
import os
import requests
import uuid
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from captcha.image import ImageCaptcha
from flask_sqlalchemy import SQLAlchemy
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from dotenv import load_dotenv

# --- 1. 配置與初始化 (Configuration and Initialization) ---

db = SQLAlchemy()

# 模擬 os.getenv 獲取設定 (請確保您的環境變數已設定)
def safe_getenv(key, default=None):
    if os.path.exists(".env"): load_dotenv()
    return os.getenv(key, default)

app = Flask(__name__)

app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_AS_ASCII'] = False

db.init_app(app)

FAILED_LOGINS = {}
MAX_FAILED = 5
LOCK_TIME = timedelta(minutes=5)

# LINE 配置
CLIENT_ID = safe_getenv('LINE_LOGIN_CHANNEL_ID')
CLIENT_SECRET = safe_getenv('LINE_LOGIN_CHANNEL_SECRET')
URL_BASE = safe_getenv('URL')
LINE_REDIRECT_URI = f"{URL_BASE}/api/callback/line"

# Google 配置
GOOGLE_CLIENT_ID = safe_getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = safe_getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = f"{URL_BASE}/api/callback/google"

# Google OAuth 2.0 授權終端點
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"


# --- 2. 資料模型與輔助函數 (Data Model and Helpers) ---

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=True) # 允許第三方登入用戶沒有傳統帳號
    password_hash = db.Column(db.String(200), nullable=True) # 允許第三方登入用戶沒有密碼
    
    # 新增 OAuth 相關欄位
    line_user_id = db.Column(db.String(128), unique=True, nullable=True)
    google_user_id = db.Column(db.String(128), unique=True, nullable=True)
    email = db.Column(db.String(128), unique=True, nullable=True) 
    display_name = db.Column(db.String(128), nullable=True)

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.DateTime, default=datetime.now)
    content = db.Column(db.String(500), nullable=False)

# **[新增]** 用於伺服器端管理 OAuth 狀態的資料表
class OAuthState(db.Model):
    __tablename__ = 'oauth_states'
    id = db.Column(db.Integer, primary_key=True)
    state_token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    flow_type = db.Column(db.String(10), nullable=False)  # 'LOGIN' or 'LINK'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True) # Only if flow_type is 'LINK'
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)


def save_log_to_db(content):
    try:
        log = Log(content=content)
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        # print(f"Log 寫入失敗: {e}") # 避免在 API 響應中輸出錯誤
        db.session.rollback()

# 模擬 temp.py 中的 save_log 函數
def save_log(content):
    save_log_to_db(content)

with app.app_context():
    db.create_all()

def generate_captcha_hash(text):
    """將驗證碼文字加鹽雜湊，用於無狀態驗證"""
    salt = app.config['SECRET_KEY']
    return hashlib.sha256((text.upper() + salt).encode('utf-8')).hexdigest()

def verify_captcha(user_input, token):
    """驗證使用者輸入的驗證碼是否正確"""
    if not user_input or not token:
        return False
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        expected_hash = data.get('hash')
        input_hash = generate_captcha_hash(user_input)
        return input_hash == expected_hash
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return False

def get_user_jwt(user_object: User):
    """生成 API JWT"""
    access_token_payload = {
        'user': user_object.username if user_object.username else str(user_object.id), # 使用 username 或 ID 作為標識
        'id': user_object.id,
        'exp': datetime.utcnow() + timedelta(minutes=30)
    }
    return jwt.encode(access_token_payload, app.config['SECRET_KEY'], algorithm='HS256')


def token_required(f):
    """裝飾器：保護 API 路由，需驗證 Authorization Header"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        token = None
        user_id = None

        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'message': '缺少驗證 Token', 'error_code': 'MISSING_TOKEN'}), 401

        try:
            # 確保 JWT 使用 'HS256' 演算法解碼
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            username_or_id = data.get('user')
            user_id = data.get('id')
            
            # 優先使用 ID 查找，若無 ID 則使用 username 查找
            if user_id:
                current_user = User.query.filter_by(id=user_id).first()
            else:
                current_user = User.query.filter_by(username=username_or_id).first()
                
            if not current_user:
                raise Exception("User not found")
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token 已過期，請重新登入', 'error_code': 'TOKEN_EXPIRED'}), 401
        except Exception as e:
            save_log(f"Token 無效: {e}")
            return jsonify({'message': 'Token 無效', 'error_code': 'INVALID_TOKEN'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# 模擬 find_user_by_identity 函數
def find_user_by_identity(login_type, user_id=None, email=None):
    if login_type == 'line' and user_id:
        return User.query.filter_by(line_user_id=user_id).first()
    elif login_type == 'google' and (user_id or email):
        # 優先使用 google_user_id (sub)，其次使用 email
        user = User.query.filter_by(google_user_id=user_id).first()
        if not user and email:
            # 這裡暫時允許使用 email 查找，但更安全的做法是只使用 sub/provider_id
            user = User.query.filter_by(email=email).first() 
        return user
    return None

# 模擬 update_user_profile 函數 (用於註冊和綁定)
def update_user_profile(user_id=None, login_type=None, provider_id=None, display_name=None, email=None, username=None, linking_user: User=None):
    # 1. 如果是綁定流程，使用 linking_user
    if linking_user:
        user = linking_user
        # 檢查連結的帳號是否與用戶已有的傳統帳號郵件衝突
        if user.email and email and user.email != email:
            # 這是一個複雜的衝突處理，目前先允許，但在更嚴格的系統中可能需要更多驗證
            pass
        is_new_user = False
    else:
        # 2. 登入/註冊流程：嘗試透過 provider_id 查找現有用戶
        user = find_user_by_identity(login_type, provider_id, email)
        is_new_user = not user
        
        # 3. 如果找不到，則建立新用戶
        if not user:
            # 確保新用戶的 username 不與既有用戶衝突
            final_username = username
            if final_username and User.query.filter_by(username=final_username).first():
                final_username = f"user_{secrets.token_hex(4)}" # 避免衝突
                
            user = User(
                username=final_username, 
                display_name=display_name,
                email=email if email else None
            )
            db.session.add(user)
            db.session.flush() # 確保新用戶有 ID
    
    # 4. 綁定/更新社交帳號資訊
    if login_type == 'line':
        # 檢查是否已被其他帳號綁定
        if User.query.filter_by(line_user_id=provider_id).filter(User.id != user.id).first():
            return None, "此 LINE 帳號已被其他用戶綁定"
        user.line_user_id = provider_id
    elif login_type == 'google':
        # 檢查是否已被其他帳號綁定
        if User.query.filter_by(google_user_id=provider_id).filter(User.id != user.id).first():
            return None, "此 Google 帳號已被其他用戶綁定"
        user.google_user_id = provider_id
        # 只有在用戶還沒有電子郵件或電子郵件是空值時才更新，避免覆蓋傳統帳號的電子郵件
        if not user.email:
            user.email = email
    
    # 5. 更新顯示名稱 (如果用戶還沒有設定)
    if display_name and not user.display_name:
        user.display_name = display_name
    
    # 6. 提交變更
    db.session.commit()
    return user, None # 返回 User 物件和 None 錯誤


# --- 3. 既有 API 路由 (Existing API Routes) ---

@app.route("/api/captcha", methods=["GET"])
def get_captcha():
    image_gen = ImageCaptcha(width=160, height=60)
    chars = string.ascii_uppercase + string.digits
    captcha_text = ''.join(random.choices(chars, k=5))
    while "0" in captcha_text or "O" in captcha_text:
        captcha_text = ''.join(random.choices(chars, k=5))

    data = image_gen.generate(captcha_text)
    base64_img = base64.b64encode(data.getvalue()).decode('utf-8')

    token_payload = {
        'hash': generate_captcha_hash(captcha_text),
        'exp': datetime.utcnow() + timedelta(minutes=5)
    }
    captcha_token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({
        'captcha_token': captcha_token,
        'image': f"data:image/png;base64,{base64_img}"
    })

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'message': '無效的 JSON 資料', 'error_code': 'INVALID_JSON'}), 400

    username = data.get("username")
    password = data.get("password")
    confirm = data.get("confirm_password")
    captcha_input = data.get("captcha_answer")
    captcha_token = data.get("captcha_token")

    if not verify_captcha(captcha_input, captcha_token):
        return jsonify({'message': '驗證碼錯誤或已過期', 'error_code': 'CAPTCHA_FAIL'}), 400

    if not username or not password:
        return jsonify({'message': '帳號與密碼不可為空', 'error_code': 'EMPTY_FIELDS'}), 400

    if password != confirm:
        return jsonify({'message': '兩次密碼輸入不一致', 'error_code': 'PASSWORD_MISMATCH'}), 400
    
    # 檢查 username 是否已存在
    if User.query.filter_by(username=username).first():
        return jsonify({
            'message': '此帳號已經被註冊過了，請直接登入',
            'error_code': 'USER_EXISTS' 
        }), 409

    try:
        new_user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        save_log_to_db(f"API 註冊成功: {username}")

        return jsonify({
            'message': '註冊成功',
            'username': username
        }), 201
        
    except Exception as e:
        db.session.rollback()
        save_log_to_db(f"API 註冊失敗: {username} - {e}")
        return jsonify({'message': '伺服器錯誤，請稍後再試', 'error_code': 'SERVER_ERROR'}), 500

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'message': '無效的 JSON 資料'}), 400

    username = data.get("username")
    password = data.get("password")
    captcha_input = data.get("captcha_answer")
    captcha_token = data.get("captcha_token")
    now = datetime.now()

    user_record = FAILED_LOGINS.get(username)
    if user_record and 'lock_until' in user_record and now < user_record['lock_until']:
        remaining = int((user_record['lock_until'] - now).total_seconds())
        return jsonify({'message': f'帳號鎖定中，請等待 {remaining} 秒'}), 403

    if not verify_captcha(captcha_input, captcha_token):
        save_log_to_db(f"{username} API 登入失敗 - 驗證碼錯誤")
        return jsonify({'message': '驗證碼錯誤或已過期'}), 400

    user = User.query.filter_by(username=username).first()
    # 確保用戶有設定密碼 (排除純社交帳號)
    if user and user.password_hash and check_password_hash(user.password_hash, password): 
        save_log_to_db(f"{username} API 登入成功")
        if username in FAILED_LOGINS:
            del FAILED_LOGINS[username]
        
        access_token = get_user_jwt(user)

        return jsonify({
            'message': '登入成功',
            'token': access_token,
            'user': username,
            'expires_in': 1800
        }), 200

    save_log_to_db(f"{username} API 登入失敗 - 帳號或密碼錯誤")
    
    if username: # 只對有輸入 username 的情況進行鎖定追蹤
        if not user_record:
            FAILED_LOGINS[username] = {"count": 1, "last_failed": now}
        else:
            FAILED_LOGINS[username]["count"] += 1
            FAILED_LOGINS[username]["last_failed"] = now
            if FAILED_LOGINS[username]["count"] >= MAX_FAILED:
                FAILED_LOGINS[username]["lock_until"] = now + LOCK_TIME
        
        # 避免洩露用戶是否存在
        remaining = MAX_FAILED - FAILED_LOGINS[username]["count"] if username in FAILED_LOGINS else MAX_FAILED 
    else:
        remaining = MAX_FAILED

    return jsonify({'message': f'帳號或密碼錯誤，剩餘嘗試次數：{remaining}'}), 401

@app.route("/api/profile", methods=["GET"])
@token_required
def profile(current_user: User):
    """測試用的受保護路由，顯示用戶資訊"""
    return jsonify({
        'message': 'test success',
        'user_id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'display_name': current_user.display_name,
        'is_line_linked': bool(current_user.line_user_id),
        'is_google_linked': bool(current_user.google_user_id)
    })


# --- 4. 新增 API 路由 (New API Routes) ---

# 4.1. 變更使用者名稱
@app.route("/api/user/username", methods=["POST"])
@token_required
def change_username(current_user: User):
    data = request.get_json()
    new_username = data.get('new_username')

    if not new_username or len(new_username) < 4:
        return jsonify({'message': '新使用者名稱長度必須至少為 4 個字元'}), 400

    # 檢查新名稱是否已被使用
    if User.query.filter_by(username=new_username).filter(User.id != current_user.id).first():
        return jsonify({'message': '此使用者名稱已被使用'}), 409

    try:
        old_username = current_user.username
        current_user.username = new_username
        db.session.commit()
        save_log_to_db(f"用戶 {old_username or current_user.id} 成功變更使用者名稱為 {new_username}")
        
        # 重新發放一個新的 JWT
        new_token = get_user_jwt(current_user)
        
        return jsonify({
            'message': '使用者名稱變更成功',
            'new_username': new_username,
            'token': new_token,
            'expires_in': 1800
        }), 200
    except Exception as e:
        db.session.rollback()
        save_log_to_db(f"變更使用者名稱失敗 (ID: {current_user.id}): {e}")
        return jsonify({'message': '伺服器錯誤，變更失敗'}), 500

# 4.2. 變更密碼
@app.route("/api/user/password", methods=["POST"])
@token_required
def change_password(current_user: User):
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    if not current_user.password_hash:
        return jsonify({'message': '您的帳號是透過第三方登入註冊，請先透過此 API 設定一組密碼'}), 400
    
    if not old_password or not new_password or not confirm_password:
        return jsonify({'message': '所有欄位皆不可為空'}), 400
    
    if new_password != confirm_password:
        return jsonify({'message': '兩次新密碼輸入不一致'}), 400

    if len(new_password) < 6:
        return jsonify({'message': '新密碼長度必須至少為 6 個字元'}), 400

    if not check_password_hash(current_user.password_hash, old_password):
        return jsonify({'message': '舊密碼輸入錯誤'}), 401

    try:
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        save_log_to_db(f"用戶 {current_user.username or current_user.id} 成功變更密碼")
        return jsonify({'message': '密碼變更成功'}), 200
    except Exception as e:
        db.session.rollback()
        save_log_to_db(f"變更密碼失敗 (ID: {current_user.id}): {e}")
        return jsonify({'message': '伺服器錯誤，變更失敗'}), 500

# 4.3. 綁定 LINE 帳號 (步驟 1: 導向 LINE 授權頁)
@app.route("/api/link/line/init", methods=["GET"])
@token_required
def link_line_init(current_user: User):
    if current_user.line_user_id:
        return jsonify({'message': '您的帳號已綁定 LINE'}), 400

    state = secrets.token_hex(32)
    expires = datetime.now() + timedelta(minutes=5)
    
    # **[安全修正]** 將 state 資訊儲存在資料庫中，不傳遞給前端
    try:
        new_state = OAuthState(
            state_token=state,
            flow_type='LINK',
            user_id=current_user.id,
            expires_at=expires
        )
        db.session.add(new_state)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        save_log_to_db(f"儲存 LINE 綁定 State 失敗: {e}")
        return jsonify({'message': '伺服器錯誤，無法產生授權狀態'}), 500
    
    login_url = (
        f"https://access.line.me/oauth2/v2.1/authorize"
        f"?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={LINE_REDIRECT_URI}"
        f"&scope=openid%20profile%20email"
        f"&state={state}" # 只傳遞 state token
    )
    
    return jsonify({
        'message': '請導向此 URL 進行 LINE 帳號綁定',
        'auth_url': login_url
    }), 200

# 4.4. 綁定 GOOGLE 帳號 (步驟 1: 導向 GOOGLE 授權頁)
@app.route("/api/link/google/init", methods=["GET"])
@token_required
def link_google_init(current_user: User):
    if current_user.google_user_id:
        return jsonify({'message': '您的帳號已綁定 Google'}), 400

    state = secrets.token_hex(32)
    expires = datetime.now() + timedelta(minutes=5)

    # **[安全修正]** 將 state 資訊儲存在資料庫中，不傳遞給前端
    try:
        new_state = OAuthState(
            state_token=state,
            flow_type='LINK',
            user_id=current_user.id,
            expires_at=expires
        )
        db.session.add(new_state)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        save_log_to_db(f"儲存 Google 綁定 State 失敗: {e}")
        return jsonify({'message': '伺服器錯誤，無法產生授權狀態'}), 500
    
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
        "state": state # 只傳遞 state token
    }
    auth_url = f"{GOOGLE_AUTHORIZATION_URL}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
    
    return jsonify({
        'message': '請導向此 URL 進行 Google 帳號綁定',
        'auth_url': auth_url
    }), 200

# 4.5. LINE 快速登入 (步驟 1: 導向 LINE 授權頁)
@app.route("/api/login/line/init", methods=["GET"])
def login_line_init():
    state = secrets.token_hex(32)
    expires = datetime.now() + timedelta(minutes=5)

    # **[安全修正]** 將 state 資訊儲存在資料庫中
    try:
        new_state = OAuthState(
            state_token=state,
            flow_type='LOGIN',
            user_id=None,
            expires_at=expires
        )
        db.session.add(new_state)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        save_log_to_db(f"儲存 LINE 登入 State 失敗: {e}")
        return jsonify({'message': '伺服器錯誤，無法產生授權狀態'}), 500
    
    login_url = (
        f"https://access.line.me/oauth2/v2.1/authorize"
        f"?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={LINE_REDIRECT_URI}"
        f"&scope=openid%20profile%20email"
        f"&state={state}"
    )
    return jsonify({'auth_url': login_url}), 200

# 4.6. GOOGLE 快速登入 (步驟 1: 導向 GOOGLE 授權頁)
@app.route("/api/login/google/init", methods=["GET"])
def login_google_init():
    state = secrets.token_hex(32)
    expires = datetime.now() + timedelta(minutes=5)

    # **[安全修正]** 將 state 資訊儲存在資料庫中
    try:
        new_state = OAuthState(
            state_token=state,
            flow_type='LOGIN',
            user_id=None,
            expires_at=expires
        )
        db.session.add(new_state)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        save_log_to_db(f"儲存 Google 登入 State 失敗: {e}")
        return jsonify({'message': '伺服器錯誤，無法產生授權狀態'}), 500
    
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
        "state": state
    }
    auth_url = f"{GOOGLE_AUTHORIZATION_URL}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
    return jsonify({'auth_url': auth_url}), 200


# --- 5. OAuth 回調 API 路由 (OAuth Callback API Routes) ---

# 5.1. LINE 回調
@app.route("/api/callback/line", methods=["GET"])
def callback_line_api():
    code = request.args.get("code")
    state = request.args.get("state")
    
    if not code:
        save_log("LINE 授權失敗：未收到授權碼")
        return jsonify({'message': '授權失敗：未收到授權碼'}), 400
    
    # 1. **[安全修正]** 查找並驗證 State
    if not state:
         return jsonify({'message': '授權失敗：缺少 State 參數'}), 400
         
    oauth_state = OAuthState.query.filter_by(state_token=state).first()
    
    if not oauth_state or oauth_state.expires_at < datetime.now():
        # 清理無效或過期的 State
        if oauth_state:
            db.session.delete(oauth_state)
            db.session.commit()
        return jsonify({'message': '授權失敗：State 無效或已過期'}), 400
    
    flow = oauth_state.flow_type
    current_user_id = oauth_state.user_id # 只有在 'LINK' 流程中才會有值
    
    # 2. **[安全修正]** 刪除已使用的 State (防止重放攻擊)
    db.session.delete(oauth_state)
    db.session.commit()


    # 3. 獲取 Token 和用戶資訊 (與原邏輯相同)
    token_url = "https://api.line.me/oauth2/v2.1/token"
    payload = {
        "grant_type": "authorization_code", "code": code, "redirect_uri": LINE_REDIRECT_URI,
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_response = requests.post(token_url, data=payload, headers=headers)

    if token_response.status_code != 200:
        save_log(f"無法從 LINE 獲取 Access Token: {token_response.text}")
        return jsonify({'message': '無法從 LINE 獲取 Access Token'}), 500

    token_data = token_response.json()
    id_token_jwt = token_data.get("id_token")
    
    if not id_token_jwt:
        return jsonify({'message': '無法從 LINE 獲取 ID Token'}), 500

    try:
        decoded = jwt.decode(id_token_jwt, CLIENT_SECRET, audience=CLIENT_ID, algorithms=["HS256"])
        provider_id = decoded.get("sub")
        display_name = decoded.get("name", "未知")
        email = decoded.get("email")

        # 4. 處理連結流程 (LINK)
        if flow == 'LINK':
            linking_user = User.query.filter_by(id=current_user_id).first()
            if not linking_user:
                 save_log(f"LINE 連結失敗：用戶 ID {current_user_id} 不存在")
                 return jsonify({'message': '連結失敗：用戶不存在'}), 404
            
            # 執行綁定/更新操作
            updated_user, error = update_user_profile(
                login_type='line', provider_id=provider_id, display_name=display_name, email=email, linking_user=linking_user
            )

            if error:
                 save_log(f"LINE 連結失敗 (ID: {linking_user.id}): {error}")
                 return jsonify({'message': f'LINE 連結失敗: {error}'}), 409

            save_log(f"Linked Line account {provider_id} to uid {updated_user.id}")
            return jsonify({'message': 'LINE 帳號連結成功', 'is_linked': True}), 200

        # 5. 處理登入流程 (LOGIN)
        elif flow == 'LOGIN':
            found_user = find_user_by_identity(login_type='line', user_id=provider_id)
            
            if found_user:
                # 登入成功
                save_log(f"{provider_id} (Line) logged in with existing uid {found_user.id}")
                access_token = get_user_jwt(found_user)
                return jsonify({
                    'message': '登入成功',
                    'token': access_token,
                    'user': found_user.username or found_user.id,
                    'expires_in': 1800
                }), 200
            else:
                # 註冊 (自動註冊並登入)
                initial_username = display_name if display_name and not User.query.filter_by(username=display_name).first() else None
                
                new_user, error = update_user_profile(
                    login_type='line', provider_id=provider_id, display_name=display_name, email=email, username=initial_username
                )
                
                if not new_user:
                    save_log(f"LINE 自動註冊失敗: {error}")
                    return jsonify({'message': '自動註冊失敗', 'error': error}), 500

                save_log(f"{provider_id} (Line) registered with uid {new_user.id}")
                access_token = get_user_jwt(new_user)
                return jsonify({
                    'message': '註冊成功並登入',
                    'token': access_token,
                    'user': new_user.username or new_user.id,
                    'expires_in': 1800
                }), 201

        else:
            return jsonify({'message': '未知或無效的流程類型'}), 400

    except jwt.InvalidTokenError as e:
        save_log(f"LINE ID Token驗證失敗：{e}")
        return jsonify({'message': f'ID Token驗證失敗: {e}'}), 401
    except Exception as e:
        db.session.rollback()
        save_log(f"LINE 回調處理發生錯誤：{e}")
        return jsonify({'message': '伺服器內部錯誤'}), 500

# 5.2. GOOGLE 回調
@app.route("/api/callback/google", methods=["GET"])
def callback_google_api():
    code = request.args.get('code')
    state = request.args.get('state')

    if not code:
        save_log("Google 授權失敗：未收到授權碼")
        return jsonify({'message': '授權失敗：未收到授權碼'}), 400
        
    # 1. **[安全修正]** 查找並驗證 State
    if not state:
         return jsonify({'message': '授權失敗：缺少 State 參數'}), 400
         
    oauth_state = OAuthState.query.filter_by(state_token=state).first()
    
    if not oauth_state or oauth_state.expires_at < datetime.now():
        # 清理無效或過期的 State
        if oauth_state:
            db.session.delete(oauth_state)
            db.session.commit()
        return jsonify({'message': '授權失敗：State 無效或已過期'}), 400
    
    flow = oauth_state.flow_type
    current_user_id = oauth_state.user_id # 只有在 'LINK' 流程中才會有值
    
    # 2. **[安全修正]** 刪除已使用的 State (防止重放攻擊)
    db.session.delete(oauth_state)
    db.session.commit()

    # 3. 獲取 Token 和用戶資訊 (與原邏輯相同)
    token_data = {
        "code": code, "client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI, "grant_type": "authorization_code",
    }
    response = requests.post(GOOGLE_TOKEN_URL, data=token_data)
    token_info = response.json()

    if "error" in token_info:
        save_log(f"獲取 Google Token 失敗: {token_info}")
        return jsonify({'message': f'獲取 Token 失敗: {token_info.get("error_description", token_info.get("error"))}'}), 500

    id_token_jwt = token_info.get("id_token")
    if not id_token_jwt:
        return jsonify({'message': '獲取 ID Token 失敗'}), 500

    try:
        idinfo = id_token.verify_oauth2_token(id_token_jwt, google_requests.Request(), GOOGLE_CLIENT_ID)
        provider_id = idinfo['sub']
        display_name = idinfo.get('name', '未知')
        email = idinfo.get('email')

        # 4. 處理連結流程 (LINK)
        if flow == 'LINK':
            linking_user = User.query.filter_by(id=current_user_id).first()
            if not linking_user:
                 save_log(f"Google 連結失敗：用戶 ID {current_user_id} 不存在")
                 return jsonify({'message': '連結失敗：用戶不存在'}), 404
            
            # 執行綁定/更新操作
            updated_user, error = update_user_profile(
                login_type='google', provider_id=provider_id, display_name=display_name, email=email, linking_user=linking_user
            )

            if error:
                 save_log(f"Google 連結失敗 (ID: {linking_user.id}): {error}")
                 return jsonify({'message': f'Google 連結失敗: {error}'}), 409

            save_log(f"Linked Google account {email} to uid {updated_user.id}")
            return jsonify({'message': 'Google 帳號連結成功', 'is_linked': True}), 200

        # 5. 處理登入流程 (LOGIN)
        elif flow == 'LOGIN':
            found_user = find_user_by_identity(login_type='google', user_id=provider_id, email=email)
            
            if found_user:
                # 登入成功
                save_log(f"{provider_id} (Google) logged in with existing uid {found_user.id}")
                access_token = get_user_jwt(found_user)
                return jsonify({
                    'message': '登入成功',
                    'token': access_token,
                    'user': found_user.username or found_user.id,
                    'expires_in': 1800
                }), 200
            else:
                # 註冊 (自動註冊並登入)
                initial_username = display_name if display_name and not User.query.filter_by(username=display_name).first() else None
                
                new_user, error = update_user_profile(
                    login_type='google', provider_id=provider_id, display_name=display_name, email=email, username=initial_username
                )

                if not new_user:
                    save_log(f"Google 自動註冊失敗: {error}")
                    return jsonify({'message': '自動註冊失敗', 'error': error}), 500

                save_log(f"{provider_id} (Google) registered with uid {new_user.id}")
                access_token = get_user_jwt(new_user)
                return jsonify({
                    'message': '註冊成功並登入',
                    'token': access_token,
                    'user': new_user.username or new_user.id,
                    'expires_in': 1800
                }), 201

        else:
            return jsonify({'message': '未知或無效的流程類型'}), 400

    except ValueError as e:
        save_log(f"Google ID Token驗證失敗：{e}")
        return jsonify({'message': f'ID Token驗證失敗: {e}'}), 401
    except Exception as e:
        db.session.rollback()
        save_log(f"Google 回調處理發生錯誤：{e}")
        return jsonify({'message': '伺服器內部錯誤'}), 500

if __name__ == "__main__":
    app.run(debug=False, port=5000)