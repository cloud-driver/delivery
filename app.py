import jwt
import random
import string
import secrets
import hashlib
import base64
import os
import requests
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, render_template_string, flash
from werkzeug.security import generate_password_hash, check_password_hash
from captcha.image import ImageCaptcha
from flask_sqlalchemy import SQLAlchemy
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from dotenv import load_dotenv
from flask_cors import CORS
from flask_admin import Admin, BaseView, expose, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from itsdangerous import BadSignature, URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from google.cloud import speech
from google.oauth2 import service_account
import json
import subprocess
import tempfile
import time

db = SQLAlchemy()

def safe_getenv(key, default=None):
    if os.path.exists(".env"): load_dotenv()
    return os.getenv(key, default)

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = safe_getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = safe_getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_AS_ASCII'] = False
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'

ADMIN_USERNAME = safe_getenv('ADMIN_USER')
ADMIN_PASSWORD_HASH = generate_password_hash(safe_getenv('ADMIN_PASS'))

# Email 寄送設定
EMAIL_SENDER = safe_getenv('EMAIL_SENDER')
EMAIL_PASSWORD = safe_getenv('EMAIL_PASSWORD')

# LINE 配置
CLIENT_ID = safe_getenv('LINE_LOGIN_CHANNEL_ID')
CLIENT_SECRET = safe_getenv('LINE_LOGIN_CHANNEL_SECRET')
URL_BASE = safe_getenv('URL')
LINE_REDIRECT_URI = f"{URL_BASE}/api/callback/line"

# Google 配置
GOOGLE_CLIENT_ID = safe_getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = safe_getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = f"{URL_BASE}/api/callback/google"

# Google OAuth 2.0
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# 微調 LLM API 配置
# LLM_API_URL = safe_getenv('LLM_API_URL')

# 前端 URL（用於電子郵件中的連結）
FRONTEND_URL = safe_getenv('FRONTEND_URL')
FAILED_REGISTRATIONS = {}
MAX_REGISTER_FAIL = 3

db.init_app(app)

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class AdminModelView(ModelView):

    can_create = False
    def is_accessible(self):
        return session.get('is_admin') == True

    def inaccessible_callback(self, name, **kwargs):
        flash('請先登入後台。', 'warning')
        return redirect(url_for('admin_login'))
    
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return super(MyAdminIndexView, self).index()

FAILED_LOGINS = {}
MAX_FAILED = 5
LOCK_TIME = timedelta(minutes=5)

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
    flow_type = db.Column(db.String(10), nullable=False)  # 'LOGIN' or 'LINK'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True) # Only if flow_type is 'LINK'
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

def get_speech_client():
    creds_json = os.environ.get('GOOGLE_STT')
    if creds_json:
        creds_dict = json.loads(creds_json)
        credentials = service_account.Credentials.from_service_account_info(creds_dict)
        return speech.SpeechClient(credentials=credentials)
    return speech.SpeechClient()

def save_log_to_db(content):
    try:
        log = Log(content=content)
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()

def save_log(content):
    save_log_to_db(content)

def send_email(subject, body, to_email):
    from_email = EMAIL_SENDER
    password = EMAIL_PASSWORD

    if not from_email or not password:
        save_log("Email 發送失敗：未設定 EMAIL_SENDER 或 EMAIL_PASSWORD")
        return False

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html', 'utf-8')) 

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(from_email, password)
        text = msg.as_string()
        
        server.sendmail(from_email, to_email, text)
        server.quit()
        return True
    except Exception as e:
        save_log(f"Email 發送失敗 (to: {to_email}): {e}")
        return False
    
admin = Admin(app, name='e-system-delivery 的後台', index_view=MyAdminIndexView(name='首頁'))
admin.add_view(AdminModelView(User, db.session, name='使用者管理'))
admin.add_view(AdminModelView(Log, db.session, name='日誌紀錄'))
admin.add_view(AdminModelView(OAuthState, db.session, name='OAuth 狀態'))
    
with app.app_context():
    db.create_all()
    try:
        db.reflect()
        registered_tables = [User.__tablename__, Log.__tablename__, OAuthState.__tablename__]
        for table_name, table in db.metadata.tables.items():
            if table_name not in registered_tables:
                model_name = ''.join([part.capitalize() for part in table_name.split('_')])
                try:
                    dynamic_model = type(model_name, (db.Model,), {
                        '__table__': table,
                        '__module__': __name__,
                        '__mapper_args__': {'primary_key': [col for col in table.columns if col.primary_key]} 
                    })
                    admin.add_view(AdminModelView(dynamic_model, db.session, name=table_name))
                    print(f"Auto-registered table: {table_name}")
                except Exception as e:
                    print(f"Failed to register table {table_name}: {e}")
                    
    except Exception as e:
        print(f"Database reflection failed: {e}")

def generate_captcha_hash(text):
    """將驗證碼文字雜湊，用於無狀態驗證"""
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
        'user': user_object.username if user_object.username else str(user_object.id),
        'id': user_object.id,
        'exp': datetime.now(timezone.utc) + timedelta(minutes=30)
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
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            username_or_id = data.get('user')
            user_id = data.get('id')
            
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

def find_user_by_identity(login_type, user_id=None, email=None):
    if login_type == 'line' and user_id:
        return User.query.filter_by(line_user_id=user_id).first()
    elif login_type == 'google' and user_id:
        return User.query.filter_by(google_user_id=user_id).first()
    return None

def update_user_profile(user_id=None, login_type=None, provider_id=None, display_name=None, email=None, username=None, linking_user: User=None):
    if linking_user:
        user = linking_user
        if user.email and email and user.email != email:
            existing_user_with_new_email = User.query.filter_by(email=email).filter(User.id != user.id).first()
            if existing_user_with_new_email:
                error_msg = f"綁定失敗：電子郵件 {email} 已經被另一個帳號使用。"
                return None, error_msg
            user.email = email
        is_new_user = False
    else:
        user = find_user_by_identity(login_type, provider_id, email)
        is_new_user = not user
        
        if not user:
            if email:
                existing_email_user = User.query.filter_by(email=email).first()
                if existing_email_user:
                    return None, f"此 Email ({email}) 已註冊過。為確保安全，請先使用帳號密碼登入後，至個人設定頁面進行帳號綁定。"

            final_username = username
            if final_username and User.query.filter_by(username=final_username).first():
                final_username = f"user_{secrets.token_hex(4)}"
                
            user = User(
                username=final_username, 
                display_name=display_name,
                email=email if email else None
            )
            db.session.add(user)
            db.session.flush()
    
    if login_type == 'line':
        if User.query.filter_by(line_user_id=provider_id).filter(User.id != user.id).first():
            return None, "此 LINE 帳號已被其他用戶綁定"
        user.line_user_id = provider_id
    elif login_type == 'google':
        if User.query.filter_by(google_user_id=provider_id).filter(User.id != user.id).first():
            return None, "此 Google 帳號已被其他用戶綁定"
        user.google_user_id = provider_id
        if not user.email:
            user.email = email
    
    if display_name and not user.display_name:
        user.display_name = display_name
        
    db.session.commit()
    return user, None

def get_client_ip():
    """取得客戶端真實 IP (支援 Render/Proxy 環境)"""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def record_register_fail(ip):
    """記錄該 IP 的註冊失敗次數"""
    today_str = datetime.now().strftime('%Y-%m-%d')
    
    if ip not in FAILED_REGISTRATIONS:
        FAILED_REGISTRATIONS[ip] = {'count': 1, 'date': today_str}
    else:
        record = FAILED_REGISTRATIONS[ip]
        if record['date'] != today_str:
            record['date'] = today_str
            record['count'] = 1
        else:
            record['count'] += 1

@app.route("/")
def home():
    return redirect(f"{FRONTEND_URL}")

@app.route("/health")
def health_check():
    return "OK", 200

@app.route('/mic-test')
def mic_test():
    return render_template('mic.html')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['is_admin'] = True
            flash('登入成功！', 'success')
            return redirect(url_for('admin.index'))
        else:
            flash('帳號或密碼錯誤。', 'danger')
            
    if session.get('is_admin'):
        return redirect(url_for('admin.index'))

    return render_template('database_login.html')

@app.route('/admin-logout')
def admin_logout():
    session.pop('is_admin', None)
    flash('您已成功登出。', 'success')
    return redirect(url_for('admin_login'))

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
    client_ip = get_client_ip()
    today_str = datetime.now().strftime('%Y-%m-%d')

    if client_ip in FAILED_REGISTRATIONS:
        record = FAILED_REGISTRATIONS[client_ip]
        if record['date'] == today_str and record['count'] >= MAX_REGISTER_FAIL:
            save_log_to_db(f"註冊阻擋：IP {client_ip} 因失敗次數過多被暫時封鎖")
            return jsonify({
                'message': '今日註冊失敗次數過多，您的 IP 已被暫時封鎖，請明日再試。',
                'error_code': 'IP_BLOCKED'
            }), 403

    data = request.get_json()
    if not data:
        record_register_fail(client_ip)
        return jsonify({'message': '無效的 JSON 資料', 'error_code': 'INVALID_JSON'}), 400

    username = data.get("username")
    password = data.get("password")
    confirm = data.get("confirm_password")
    email = data.get("email")

    if not username or not password or not email:
        record_register_fail(client_ip)
        return jsonify({'message': '帳號、密碼與 Email 不可為空', 'error_code': 'EMPTY_FIELDS'}), 400

    if not email.endswith('@gmail.com'):
         record_register_fail(client_ip)
         return jsonify({'message': '目前僅支援 @gmail.com 註冊', 'error_code': 'GMAIL_ONLY'}), 400

    if password != confirm:
        record_register_fail(client_ip)
        return jsonify({'message': '兩次密碼輸入不一致', 'error_code': 'PASSWORD_MISMATCH'}), 400
    
    if User.query.filter((User.username == username) | (User.email == email)).first():
        record_register_fail(client_ip)
        return jsonify({
            'message': '此帳號或 Email 已經被註冊過了',
            'error_code': 'USER_EXISTS' 
        }), 409

    try:
        password_hash = generate_password_hash(password)
        
        data_to_sign = {
            'username': username, 
            'password_hash': password_hash, 
            'email': email
        }
        token = s.dumps(data_to_sign, salt='email-confirm')
        
        if not URL_BASE:
             save_log("註冊失敗：未設定 URL_BASE 環境變數")
             record_register_fail(client_ip)
             return jsonify({'message': '伺服器設定錯誤', 'error_code': 'CONFIG_ERROR'}), 500
             
        verification_url = f"{URL_BASE}/api/verify-email/{token}"
        
        email_subject = "【e-system-delivery】請驗證您的 Email"
        email_body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
            <h2 style="color: #333;">歡迎加入，{username}！</h2>
            <p style="font-size: 16px; color: #555;">
                感謝您註冊本服務。<br>
                請點擊下方的按鈕以完成 Email 驗證並啟用您的帳號：
            </p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{verification_url}" style="background-color: #008cff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 16px; display: inline-block;">
                    啟用我的帳號
                </a>
            </div>
            <p style="font-size: 14px; color: #999;">
                連結有效期限為 10 分鐘。<br>
                如果您無法點擊上方按鈕，請複製以下連結至瀏覽器：<br>
                <a href="{verification_url}" style="color: #008cff;">{verification_url}</a>
            </p>
        </div>
        """
        if not send_email(email_subject, email_body, email):
            save_log_to_db(f"API 註冊 {username} 失敗：Email 發送失敗")
            record_register_fail(client_ip)
            return jsonify({'message': '註冊失敗：無法發送驗證信', 'error_code': 'EMAIL_SEND_FAIL'}), 500

        save_log_to_db(f"API 註冊 {username} ({email})：驗證信已寄出 (IP: {client_ip})")

        return jsonify({
            'message': '註冊請求成功，請至您的 Gmail 信箱點擊驗證按鈕以啟用帳號。',
            'username': username
        }), 202
        
    except Exception as e:
        db.session.rollback()
        save_log_to_db(f"API 註冊失敗 (Catch): {username} - {e}")
        record_register_fail(client_ip)
        return jsonify({'message': '伺服器錯誤，請稍後再試', 'error_code': 'SERVER_ERROR'}), 500

@app.route("/api/verify-email/<token>", methods=["GET"])
def verify_email(token):
    try:
        data = s.loads(token, salt='email-confirm', max_age=600)
    except SignatureExpired:
        save_log(f"Email 驗證失敗：Token 已過期")
        return redirect(f"{FRONTEND_URL}/success.html?status=error&msg=token_expired")
    except (BadTimeSignature, BadSignature):
        save_log(f"Email 驗證失敗：Token 無效")
        return redirect(f"{FRONTEND_URL}/success.html?status=error&msg=invalid_token")
    
    username = data.get('username')
    email = data.get('email')
    password_hash = data.get('password_hash')

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return redirect(f"{FRONTEND_URL}/success.html?status=already_verified")

    try:
        new_user = User(
            username=username, 
            password_hash=password_hash,
            email=email,
            display_name=username
        )
        db.session.add(new_user)
        db.session.commit()
        save_log_to_db(f"Email 驗證成功: {username}")

        return redirect(f"{FRONTEND_URL}/success.html?status=success&username={username}")
        
    except Exception as e:
        db.session.rollback()
        save_log_to_db(f"Email 驗證失敗 (DB): {e}")
        return redirect(f"{FRONTEND_URL}/success.html?status=error&msg=server_error")

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
    
    if username:
        if not user_record:
            FAILED_LOGINS[username] = {"count": 1, "last_failed": now}
        else:
            FAILED_LOGINS[username]["count"] += 1
            FAILED_LOGINS[username]["last_failed"] = now
            if FAILED_LOGINS[username]["count"] >= MAX_FAILED:
                FAILED_LOGINS[username]["lock_until"] = now + LOCK_TIME
        
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


@app.route("/api/user/username", methods=["POST"])
@token_required
def change_username(current_user: User):
    data = request.get_json()
    new_username = data.get('new_username')

    if not new_username or len(new_username) < 4:
        return jsonify({'message': '新使用者名稱長度必須至少為 4 個字元'}), 400

    if User.query.filter_by(username=new_username).filter(User.id != current_user.id).first():
        return jsonify({'message': '此使用者名稱已被使用'}), 409

    try:
        old_username = current_user.username
        current_user.username = new_username
        db.session.commit()
        save_log_to_db(f"用戶 {old_username or current_user.id} 成功變更使用者名稱為 {new_username}")
        
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

@app.route("/api/link/line/init", methods=["GET"])
@token_required
def link_line_init(current_user: User):
    if current_user.line_user_id:
        return jsonify({'message': '您的帳號已綁定 LINE'}), 400

    state = secrets.token_hex(32)
    expires = datetime.now() + timedelta(minutes=5)
    
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
        f"&state={state}"
        f"&bot_prompt=normal"
    )
    
    return jsonify({
        'message': '請導向此 URL 進行 LINE 帳號綁定',
        'auth_url': login_url
    }), 200

@app.route("/api/link/google/init", methods=["GET"])
@token_required
def link_google_init(current_user: User):
    if current_user.google_user_id:
        return jsonify({'message': '您的帳號已綁定 Google'}), 400

    state = secrets.token_hex(32)
    expires = datetime.now() + timedelta(minutes=5)

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
        "state": state
    }
    auth_url = f"{GOOGLE_AUTHORIZATION_URL}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
    
    return jsonify({
        'message': '請導向此 URL 進行 Google 帳號綁定',
        'auth_url': auth_url
    }), 200

@app.route("/api/login/line/init", methods=["GET"])
def login_line_init():
    state = secrets.token_hex(32)
    expires = datetime.now() + timedelta(minutes=5)

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
        f"&bot_prompt=normal"
    )
    return jsonify({'auth_url': login_url}), 200

@app.route("/api/login/google/init", methods=["GET"])
def login_google_init():
    state = secrets.token_hex(32)
    expires = datetime.now() + timedelta(minutes=5)

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

@app.route("/api/callback/line", methods=["GET"])
def callback_line_api():
    code = request.args.get("code")
    state = request.args.get("state")
    
    if not code:
        save_log("LINE 授權失敗：未收到授權碼")
        return jsonify({'message': '授權失敗：未收到授權碼'}), 400
    
    if not state:
         return jsonify({'message': '授權失敗：缺少 State 參數'}), 400
         
    oauth_state = OAuthState.query.filter_by(state_token=state).first()
    
    if not oauth_state or oauth_state.expires_at < datetime.now():
        if oauth_state:
            db.session.delete(oauth_state)
            db.session.commit()
        return jsonify({'message': '授權失敗：State 無效或已過期'}), 400
    
    flow = oauth_state.flow_type
    current_user_id = oauth_state.user_id
    
    db.session.delete(oauth_state)
    db.session.commit()

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

        if flow == 'LINK':
            linking_user = User.query.filter_by(id=current_user_id).first()
            if not linking_user:
                 save_log(f"LINE 連結失敗：用戶 ID {current_user_id} 不存在")
                 return jsonify({'message': '連結失敗：用戶不存在'}), 404
            
            updated_user, error = update_user_profile(
                login_type='line', provider_id=provider_id, display_name=display_name, email=email, linking_user=linking_user
            )

            if error:
                 save_log(f"LINE 連結失敗 (ID: {linking_user.id}): {error}")
                 return jsonify({'message': f'LINE 連結失敗: {error}'}), 409

            save_log(f"Linked Line account {provider_id} to uid {updated_user.id}")
            return jsonify({'message': 'LINE 帳號連結成功', 'is_linked': True}), 200

        elif flow == 'LOGIN':
            found_user = find_user_by_identity(login_type='line', user_id=provider_id)
            
            if found_user:
                save_log(f"{provider_id} (Line) logged in with existing uid {found_user.id}")
                access_token = get_user_jwt(found_user)
                return jsonify({
                    'message': '登入成功',
                    'token': access_token,
                    'user': found_user.username or found_user.id,
                    'expires_in': 1800
                }), 200
            else:
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

@app.route("/api/callback/google", methods=["GET"])
def callback_google_api():
    code = request.args.get('code')
    state = request.args.get('state')

    if not code:
        save_log("Google 授權失敗：未收到授權碼")
        return jsonify({'message': '授權失敗：未收到授權碼'}), 400
        
    if not state:
         return jsonify({'message': '授權失敗：缺少 State 參數'}), 400
         
    oauth_state = OAuthState.query.filter_by(state_token=state).first()
    
    if not oauth_state or oauth_state.expires_at < datetime.now():
        if oauth_state:
            db.session.delete(oauth_state)
            db.session.commit()
        return jsonify({'message': '授權失敗：State 無效或已過期'}), 400
    
    flow = oauth_state.flow_type
    current_user_id = oauth_state.user_id
    
    db.session.delete(oauth_state)
    db.session.commit()

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

        if flow == 'LINK':
            linking_user = User.query.filter_by(id=current_user_id).first()
            if not linking_user:
                 save_log(f"Google 連結失敗：用戶 ID {current_user_id} 不存在")
                 return jsonify({'message': '連結失敗：用戶不存在'}), 404
            
            updated_user, error = update_user_profile(
                login_type='google', provider_id=provider_id, display_name=display_name, email=email, linking_user=linking_user
            )

            if error:
                 save_log(f"Google 連結失敗 (ID: {linking_user.id}): {error}")
                 return jsonify({'message': f'Google 連結失敗: {error}'}), 409

            save_log(f"Linked Google account {email} to uid {updated_user.id}")
            return jsonify({'message': 'Google 帳號連結成功', 'is_linked': True}), 200

        elif flow == 'LOGIN':
            found_user = find_user_by_identity(login_type='google', user_id=provider_id, email=email)
            
            if found_user:
                save_log(f"{provider_id} (Google) logged in with existing uid {found_user.id}")
                access_token = get_user_jwt(found_user)
                return jsonify({
                    'message': '登入成功',
                    'token': access_token,
                    'user': found_user.username or found_user.id,
                    'expires_in': 1800
                }), 200
            else:
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
    
@app.route('/api/ai/stt', methods=['POST'])
def stt():
    data = request.get_json()
    if not data or 'audio_base64' not in data:
        return jsonify({"error": "Missing audio_base64"}), 400

    temp_input_path = None
    temp_wav_path = None

    try:
        audio_data = data['audio_base64']
        if "," in audio_data:
            audio_data = audio_data.split(",")[1]
        audio_bytes = base64.b64decode(audio_data)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dat") as temp_input:
            temp_input.write(audio_bytes)
            temp_input_path = temp_input.name

        temp_wav_path = temp_input_path + "_converted.wav"

        # -i: 輸入
        # -ar 16000: 取樣率 16kHz
        # -ac 1: 單聲道
        # -c:a pcm_s16le: 16-bit PCM 編碼
        # -y: 若檔案存在則覆蓋
        command = [
            'ffmpeg', '-y',
            '-i', temp_input_path,
            '-ar', '16000',
            '-ac', '1',
            '-c:a', 'pcm_s16le',
            temp_wav_path
        ]
        
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        with open(temp_wav_path, "rb") as wav_file:
            converted_content = wav_file.read()

        client = get_speech_client()
        audio = speech.RecognitionAudio(content=converted_content)
        config = speech.RecognitionConfig(
            language_code="zh-TW",
            enable_automatic_punctuation=True,
            encoding=speech.RecognitionConfig.AudioEncoding.LINEAR16,
            sample_rate_hertz=16000,
            audio_channel_count=1
        )

        response = client.recognize(config=config, audio=audio)

        text = ""
        for result in response.results:
            text += result.alternatives[0].transcript

        return jsonify({"text": text}), 200

    except subprocess.CalledProcessError as e:
        print(f"FFmpeg conversion failed: {e.stderr.decode()}")
        return jsonify({"error": "Audio conversion failed. Please ensure the file is valid."}), 400
    except Exception as e:
        print(f"STT Error: {str(e)}")
        return jsonify({"error": str(e)}), 500
        
    finally:
        if temp_input_path and os.path.exists(temp_input_path):
            os.remove(temp_input_path)
        if temp_wav_path and os.path.exists(temp_wav_path):
            os.remove(temp_wav_path)

@app.route('/api/ai/stt/mock', methods=['POST'])
def mock_stt():
    """
    這是一個假的 STT API，用於前端測試。
    它不處理音檔，只會模擬延遲並回傳隨機文字。
    """
    data = request.get_json()
    if not data or 'audio_base64' not in data:
        return jsonify({"error": "Missing audio_base64"}), 400
    
    time.sleep(random.uniform(1.0, 2.5))
    
    mock_messages = [
        "這是一個測試回應，你的麥克風運作正常！",
        "我聽到了，但我是假的 AI，所以我不知道你在說什麼。",
        "測試成功！前端樣式看起來不錯喔。",
        "Hello World! 這是後端隨機回傳的字串。",
        "系統運作正常，請繼續開發您的應用程式。"
    ]
    
    return jsonify({
        "text": random.choice(mock_messages)
    })

@app.route('/api/ai/recommend', methods=['POST'])
def recommend_restaurants():
    """
    API: 接收前端傳來的 User Input 與 Tags，回傳推薦餐廳
    支援 Mock Data 與 自定義 LLM API
    """
    data = request.get_json()
    if not data:
        return jsonify({'message': '無效的 JSON 資料'}), 400

    user_input = data.get('user_input', '')
    user_tags = data.get('user_tags', [])
    
    # --- 1. 串接準備：建立 Prompt ---
    tags_str = ", ".join(user_tags)
    prompt = f"""
    你是專業的美食推薦助手。
    使用者的需求是："{user_input}"
    使用者的偏好標籤是：[{tags_str}]
    
    請根據上述資訊，從資料庫中推薦 3 間最適合的餐廳。
    請直接回傳 JSON 格式，包含 id, name, description, rating, image_url, tags。
    """
    
    # if LLM_API_URL:
    #     try:
    #         payload = {
    #             "prompt": prompt,
    #             "max_tokens": 500,
    #             "temperature": 0.7
    #             # "user_id": current_user.id
    #         }
    #         
    #         headers = {"Content-Type": "application/json"}
    #         response = requests.post(LLM_API_URL, json=payload, headers=headers, timeout=30)
    #         response.raise_for_status()
    #
    #         result_data = response.json()
    #         return jsonify(result_data)
    #
    #     except requests.exceptions.RequestException as e:
    #         print(f"LLM API Connection Error: {e}")
    #         return jsonify({'error': 'AI Service Unavailable'}), 503

    time.sleep(1.5)
    
    mock_response = {
        "status": "success",
        "data": {
            "user_intent_analysis": f"偵測到你想吃：{user_input} (偏好: {tags_str})",
            "recommendations": [
                {
                    "id": 101,
                    "name": "健康輕食餐盒",
                    "description": "低油低鹽，健康無負擔，適合注重養生的您。",
                    "image_url": "https://placehold.co/600x400?text=Healthy+Food",
                    "tags": ["健康", "水煮", "低卡"],
                    "rating": 4.8,
                    "delivery_time": "25-35 min"
                },
                {
                    "id": 102,
                    "name": "日式清爽烏龍麵",
                    "description": "柴魚高湯熬煮，口感清爽不油膩，搭配新鮮炸蝦。",
                    "image_url": "https://placehold.co/600x400?text=Udon",
                    "tags": ["日式", "麵食", "清淡"],
                    "rating": 4.5,
                    "delivery_time": "30-40 min"
                },
                {
                    "id": 103,
                    "name": "川味麻辣燙 (測試標籤)",
                    "description": "正宗四川口味，香辣過癮，挑戰你的味蕾極限。",
                    "image_url": "https://placehold.co/600x400?text=Spicy+Hotpot",
                    "tags": ["辣味", "重口味", "宵夜"],
                    "rating": 4.2,
                    "delivery_time": "40-50 min"
                }
            ]
        }
    }
    
    return jsonify(mock_response), 200

@app.route('/api/pay')
def pay():
    data = request.get_json()
    order_id = data.get('order_id')
    # 這裡會是支付邏輯
    # 這裡會更新資料庫中的訂單狀態
    # 這裡要通知商家和用戶支付成功
    return jsonify({
                    'message': '付款成功',
                    'order_id': order_id,
                    "status": "Paid"
                }), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000)) 
    print(f"Starting Flask development server on http://127.0.0.1:{port}...")
    app.run(host='0.0.0.0', port=port)