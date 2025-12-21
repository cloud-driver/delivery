import os
import json
import smtplib
import hashlib
import jwt
import secrets
from functools import wraps
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import request, jsonify, current_app
from dotenv import load_dotenv
from extensions import db
from models import Log, User

def safe_getenv(key, default=None):
    if os.path.exists(".env"): load_dotenv()
    return os.getenv(key, default)

FAILED_REGISTRATIONS = {}
FAILED_LOGINS = {}
MAX_REGISTER_FAIL = 3
MAX_FAILED = 5
LOCK_TIME = timedelta(minutes=5)

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
    from_email = safe_getenv('EMAIL_SENDER')
    password = safe_getenv('EMAIL_PASSWORD')

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

def generate_captcha_hash(text):
    salt = current_app.config['SECRET_KEY']
    return hashlib.sha256((text.upper() + salt).encode('utf-8')).hexdigest()

def verify_captcha(user_input, token):
    if not user_input or not token:
        return False
    try:
        data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        expected_hash = data.get('hash')
        input_hash = generate_captcha_hash(user_input)
        return input_hash == expected_hash
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return False

def get_user_jwt(user_object: User):
    access_token_payload = {
        'user': user_object.username if user_object.username else str(user_object.id),
        'id': user_object.id,
        'exp': datetime.now(timezone.utc) + timedelta(minutes=30)
    }
    return jwt.encode(access_token_payload, current_app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
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
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
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
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def record_register_fail(ip):
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