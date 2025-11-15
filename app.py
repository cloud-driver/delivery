import jwt
import random
import string
import secrets
import hashlib
import base64
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from captcha.image import ImageCaptcha
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.DateTime, default=datetime.now)
    content = db.Column(db.String(500), nullable=False)

def save_log_to_db(content):
    try:
        log = Log(content=content)
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Log 寫入失敗: {e}")
        db.session.rollback()

app = Flask(__name__)

app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_AS_ASCII'] = False

db.init_app(app)

FAILED_LOGINS = {}
MAX_FAILED = 5
LOCK_TIME = timedelta(minutes=5)

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

def token_required(f):
    """裝飾器：保護 API 路由，需驗證 Authorization Header"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        token = None

        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'message': '缺少驗證 Token'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(username=data['user']).first()
            if not current_user:
                raise Exception("User not found")
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token 已過期，請重新登入'}), 401
        except Exception:
            return jsonify({'message': 'Token 無效'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

@app.route("/api/captcha", methods=["GET"])
def get_captcha():
    """
    取得驗證碼 API
    回傳:
    - captcha_token: 包含驗證碼解答雜湊的 JWT (時效 5 分鐘)
    - image: Base64 編碼的圖片字串
    """
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
    if user and check_password_hash(user.password_hash, password):
        save_log_to_db(f"{username} API 登入成功")
        if username in FAILED_LOGINS:
            del FAILED_LOGINS[username]
        
        access_token_payload = {
            'user': username,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }
        access_token = jwt.encode(access_token_payload, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({
            'message': '登入成功',
            'token': access_token,
            'user': username,
            'expires_in': 1800
        }), 200

    save_log_to_db(f"{username} API 登入失敗 - 密碼錯誤")
    
    if not user_record:
        FAILED_LOGINS[username] = {"count": 1, "last_failed": now}
    else:
        FAILED_LOGINS[username]["count"] += 1
        FAILED_LOGINS[username]["last_failed"] = now
        if FAILED_LOGINS[username]["count"] >= MAX_FAILED:
            FAILED_LOGINS[username]["lock_until"] = now + LOCK_TIME
    
    remaining = MAX_FAILED - FAILED_LOGINS[username]["count"]
    return jsonify({'message': f'帳號或密碼錯誤，剩餘嘗試次數：{remaining}'}), 401

@app.route("/api/profile", methods=["GET"])
@token_required
def profile(current_user):
    """測試用的受保護路由"""
    return jsonify({
        'message': 'test success',
        'user_id': current_user.id
    })

if __name__ == "__main__":
    app.run(debug=False, port=5000)