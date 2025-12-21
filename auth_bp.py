import base64
import random
import string
import secrets
import jwt
import requests
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, redirect, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from captcha.image import ImageCaptcha
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature, BadSignature
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from extensions import db
from models import User, OAuthState
from utils import (
    safe_getenv, save_log, save_log_to_db, send_email, 
    generate_captcha_hash, verify_captcha, get_user_jwt, 
    token_required, find_user_by_identity, update_user_profile, 
    get_client_ip, record_register_fail,
    FAILED_REGISTRATIONS, FAILED_LOGINS, MAX_REGISTER_FAIL, MAX_FAILED, LOCK_TIME
)

auth_bp = Blueprint('auth', __name__)

URL_BASE = safe_getenv('URL')
FRONTEND_URL = safe_getenv('FRONTEND_URL')

CLIENT_ID = safe_getenv('LINE_LOGIN_CHANNEL_ID')
CLIENT_SECRET = safe_getenv('LINE_LOGIN_CHANNEL_SECRET')
LINE_REDIRECT_URI = f"{URL_BASE}/api/callback/line"

GOOGLE_CLIENT_ID = safe_getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = safe_getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = f"{URL_BASE}/api/callback/google"
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

def get_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

@auth_bp.route("/api/captcha", methods=["GET"])
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
    captcha_token = jwt.encode(token_payload, current_app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({
        'captcha_token': captcha_token,
        'image': f"data:image/png;base64,{base64_img}"
    })

@auth_bp.route("/api/register", methods=["POST"])
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
        
        s = get_serializer()
        token = s.dumps(data_to_sign, salt='email-confirm')
        
        verification_url = f"{URL_BASE}/api/verify-email/{token}"
        email_subject = "【e-system-delivery】請驗證您的 Email"
        email_body = f"""
        <div style="font-family: Arial, sans-serif;">
            <h2>歡迎加入，{username}！</h2>
            <p>請點擊下方按鈕以完成驗證：</p>
            <a href="{verification_url}">啟用我的帳號</a>
        </div>
        """
        
        if not send_email(email_subject, email_body, email):
            save_log_to_db(f"API 註冊 {username} 失敗：Email 發送失敗")
            record_register_fail(client_ip)
            return jsonify({'message': '註冊失敗：無法發送驗證信', 'error_code': 'EMAIL_SEND_FAIL'}), 500

        save_log_to_db(f"API 註冊 {username} ({email})：驗證信已寄出 (IP: {client_ip})")
        return jsonify({'message': '註冊請求成功，請至信箱驗證。', 'username': username}), 202
        
    except Exception as e:
        db.session.rollback()
        save_log_to_db(f"API 註冊失敗 (Catch): {username} - {e}")
        record_register_fail(client_ip)
        return jsonify({'message': '伺服器錯誤', 'error_code': 'SERVER_ERROR'}), 500

@auth_bp.route("/api/verify-email/<token>", methods=["GET"])
def verify_email(token):
    s = get_serializer()
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
        new_user = User(username=username, password_hash=password_hash, email=email, display_name=username)
        db.session.add(new_user)
        db.session.commit()
        save_log_to_db(f"Email 驗證成功: {username}")
        return redirect(f"{FRONTEND_URL}/success.html?status=success&username={username}")
    except Exception as e:
        db.session.rollback()
        save_log_to_db(f"Email 驗證失敗 (DB): {e}")
        return redirect(f"{FRONTEND_URL}/success.html?status=error&msg=server_error")

@auth_bp.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data: return jsonify({'message': '無效的 JSON 資料'}), 400

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
        if username in FAILED_LOGINS: del FAILED_LOGINS[username]
        return jsonify({'message': '登入成功', 'token': get_user_jwt(user), 'user': username, 'expires_in': 1800}), 200

    save_log_to_db(f"{username} API 登入失敗 - 帳號或密碼錯誤")
    if username:
        if not user_record: FAILED_LOGINS[username] = {"count": 1, "last_failed": now}
        else:
            FAILED_LOGINS[username]["count"] += 1
            FAILED_LOGINS[username]["last_failed"] = now
            if FAILED_LOGINS[username]["count"] >= MAX_FAILED: FAILED_LOGINS[username]["lock_until"] = now + LOCK_TIME
        remaining = MAX_FAILED - FAILED_LOGINS[username]["count"] if username in FAILED_LOGINS else MAX_FAILED 
    else: remaining = MAX_FAILED
    return jsonify({'message': f'帳號或密碼錯誤，剩餘嘗試次數：{remaining}'}), 401

@auth_bp.route("/api/profile", methods=["GET"])
@token_required
def profile(current_user: User):
    return jsonify({
        'message': 'test success',
        'user_id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'display_name': current_user.display_name,
        'is_line_linked': bool(current_user.line_user_id),
        'is_google_linked': bool(current_user.google_user_id)
    })

@auth_bp.route("/api/user/username", methods=["POST"])
@token_required
def change_username(current_user: User):
    data = request.get_json()
    new_username = data.get('new_username')
    if not new_username or len(new_username) < 4: return jsonify({'message': '長度需至少 4 字元'}), 400
    if User.query.filter_by(username=new_username).filter(User.id != current_user.id).first():
        return jsonify({'message': '此名稱已被使用'}), 409
    try:
        current_user.username = new_username
        db.session.commit()
        return jsonify({'message': '變更成功', 'new_username': new_username, 'token': get_user_jwt(current_user)}), 200
    except Exception:
        db.session.rollback()
        return jsonify({'message': '伺服器錯誤'}), 500

@auth_bp.route("/api/user/password", methods=["POST"])
@token_required
def change_password(current_user: User):
    data = request.get_json()
    old_password, new_password, confirm_password = data.get('old_password'), data.get('new_password'), data.get('confirm_password')
    if not current_user.password_hash: return jsonify({'message': '請先設定密碼'}), 400
    if not all([old_password, new_password, confirm_password]): return jsonify({'message': '欄位不可為空'}), 400
    if new_password != confirm_password: return jsonify({'message': '密碼不一致'}), 400
    if len(new_password) < 6: return jsonify({'message': '密碼過短'}), 400
    if not check_password_hash(current_user.password_hash, old_password): return jsonify({'message': '舊密碼錯誤'}), 401
    try:
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        return jsonify({'message': '密碼變更成功'}), 200
    except:
        db.session.rollback()
        return jsonify({'message': '伺服器錯誤'}), 500

@auth_bp.route("/api/link/line/init", methods=["GET"])
@token_required
def link_line_init(current_user: User):
    if current_user.line_user_id: return jsonify({'message': '已綁定 LINE'}), 400
    state = secrets.token_hex(32)
    try:
        db.session.add(OAuthState(state_token=state, flow_type='LINK', user_id=current_user.id, expires_at=datetime.now() + timedelta(minutes=5)))
        db.session.commit()
    except: db.session.rollback(); return jsonify({'message': 'Error'}), 500
    login_url = f"https://access.line.me/oauth2/v2.1/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={LINE_REDIRECT_URI}&scope=openid%20profile%20email&state={state}&bot_prompt=normal"
    return jsonify({'message': '請導向', 'auth_url': login_url}), 200

@auth_bp.route("/api/link/google/init", methods=["GET"])
@token_required
def link_google_init(current_user: User):
    if current_user.google_user_id: return jsonify({'message': '已綁定 Google'}), 400
    state = secrets.token_hex(32)
    try:
        db.session.add(OAuthState(state_token=state, flow_type='LINK', user_id=current_user.id, expires_at=datetime.now() + timedelta(minutes=5)))
        db.session.commit()
    except: db.session.rollback(); return jsonify({'message': 'Error'}), 500
    params = {"client_id": GOOGLE_CLIENT_ID, "redirect_uri": GOOGLE_REDIRECT_URI, "response_type": "code", "scope": "openid email profile", "access_type": "offline", "prompt": "consent", "state": state}
    return jsonify({'message': '請導向', 'auth_url': f"{GOOGLE_AUTHORIZATION_URL}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"}), 200

@auth_bp.route("/api/login/line/init", methods=["GET"])
def login_line_init():
    state = secrets.token_hex(32)
    try:
        db.session.add(OAuthState(state_token=state, flow_type='LOGIN', user_id=None, expires_at=datetime.now() + timedelta(minutes=5)))
        db.session.commit()
    except: db.session.rollback(); return jsonify({'message': 'Error'}), 500
    login_url = f"https://access.line.me/oauth2/v2.1/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={LINE_REDIRECT_URI}&scope=openid%20profile%20email&state={state}&bot_prompt=normal"
    return jsonify({'auth_url': login_url}), 200

@auth_bp.route("/api/login/google/init", methods=["GET"])
def login_google_init():
    state = secrets.token_hex(32)
    try:
        db.session.add(OAuthState(state_token=state, flow_type='LOGIN', user_id=None, expires_at=datetime.now() + timedelta(minutes=5)))
        db.session.commit()
    except: db.session.rollback(); return jsonify({'message': 'Error'}), 500
    params = {"client_id": GOOGLE_CLIENT_ID, "redirect_uri": GOOGLE_REDIRECT_URI, "response_type": "code", "scope": "openid email profile", "access_type": "offline", "prompt": "consent", "state": state}
    return jsonify({'auth_url': f"{GOOGLE_AUTHORIZATION_URL}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"}), 200

@auth_bp.route("/api/callback/line", methods=["GET"])
def callback_line_api():
    code, state = request.args.get("code"), request.args.get("state")
    if not code or not state: return jsonify({'message': '缺少參數'}), 400
    oauth_state = OAuthState.query.filter_by(state_token=state).first()
    if not oauth_state or oauth_state.expires_at < datetime.now():
        if oauth_state: db.session.delete(oauth_state); db.session.commit()
        return jsonify({'message': 'State 無效'}), 400
    
    flow, current_user_id = oauth_state.flow_type, oauth_state.user_id
    db.session.delete(oauth_state); db.session.commit()

    token_resp = requests.post("https://api.line.me/oauth2/v2.1/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": LINE_REDIRECT_URI,
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET
    }, headers={"Content-Type": "application/x-www-form-urlencoded"})
    
    if token_resp.status_code != 200: return jsonify({'message': '無法獲取 Token'}), 500
    try:
        decoded = jwt.decode(token_resp.json().get("id_token"), CLIENT_SECRET, audience=CLIENT_ID, algorithms=["HS256"])
        provider_id, display_name, email = decoded.get("sub"), decoded.get("name", "未知"), decoded.get("email")

        if flow == 'LINK':
            linking_user = User.query.get(current_user_id)
            if not linking_user: return jsonify({'message': '用戶不存在'}), 404
            updated_user, error = update_user_profile(login_type='line', provider_id=provider_id, display_name=display_name, email=email, linking_user=linking_user)
            if error: return jsonify({'message': error}), 409
            return jsonify({'message': '連結成功', 'is_linked': True}), 200
        elif flow == 'LOGIN':
            found_user = find_user_by_identity('line', user_id=provider_id)
            if found_user: return jsonify({'message': '登入成功', 'token': get_user_jwt(found_user), 'user': found_user.username or found_user.id, 'expires_in': 1800}), 200
            new_user, error = update_user_profile(login_type='line', provider_id=provider_id, display_name=display_name, email=email, username=display_name)
            if not new_user: return jsonify({'message': '註冊失敗', 'error': error}), 500
            return jsonify({'message': '註冊並登入成功', 'token': get_user_jwt(new_user), 'user': new_user.username, 'expires_in': 1800}), 201
    except Exception as e: return jsonify({'message': 'Server Error'}), 500

@auth_bp.route("/api/callback/google", methods=["GET"])
def callback_google_api():
    code, state = request.args.get('code'), request.args.get('state')
    if not code or not state: return jsonify({'message': '缺少參數'}), 400
    oauth_state = OAuthState.query.filter_by(state_token=state).first()
    if not oauth_state or oauth_state.expires_at < datetime.now():
        if oauth_state: db.session.delete(oauth_state); db.session.commit()
        return jsonify({'message': 'State 無效'}), 400

    flow, current_user_id = oauth_state.flow_type, oauth_state.user_id
    db.session.delete(oauth_state); db.session.commit()

    token_info = requests.post(GOOGLE_TOKEN_URL, data={
        "code": code, "client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI, "grant_type": "authorization_code"
    }).json()

    if "error" in token_info: return jsonify({'message': 'Token Error'}), 500
    try:
        idinfo = id_token.verify_oauth2_token(token_info.get("id_token"), google_requests.Request(), GOOGLE_CLIENT_ID)
        provider_id, display_name, email = idinfo['sub'], idinfo.get('name', '未知'), idinfo.get('email')

        if flow == 'LINK':
            linking_user = User.query.get(current_user_id)
            if not linking_user: return jsonify({'message': '用戶不存在'}), 404
            updated_user, error = update_user_profile(login_type='google', provider_id=provider_id, display_name=display_name, email=email, linking_user=linking_user)
            if error: return jsonify({'message': error}), 409
            return jsonify({'message': '連結成功', 'is_linked': True}), 200
        elif flow == 'LOGIN':
            found_user = find_user_by_identity('google', user_id=provider_id, email=email)
            if found_user: return jsonify({'message': '登入成功', 'token': get_user_jwt(found_user), 'user': found_user.username or found_user.id, 'expires_in': 1800}), 200
            new_user, error = update_user_profile(login_type='google', provider_id=provider_id, display_name=display_name, email=email, username=display_name)
            if not new_user: return jsonify({'message': '註冊失敗', 'error': error}), 500
            return jsonify({'message': '註冊並登入成功', 'token': get_user_jwt(new_user), 'user': new_user.username, 'expires_in': 1800}), 201
    except Exception as e: return jsonify({'message': 'Server Error'}), 500