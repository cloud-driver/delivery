import os
import json
import base64
import subprocess
import tempfile
import time
import random
import requests
from flask import Flask, jsonify, request, render_template, session, redirect, url_for, flash
from flask_cors import CORS
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from werkzeug.security import generate_password_hash, check_password_hash
from google.cloud import speech
from google.oauth2 import service_account

from extensions import db
from models import User, Log, OAuthState

from utils import safe_getenv, save_log_to_db, token_required
from auth_bp import auth_bp

try:
    from menu.app.routes.restaurant_routes import restaurant_bp
    from menu.app.routes.menu_routes import menu_bp
    from menu.app.routes.order_routes import order_bp
    from menu.app.default_index import default_bp
except ImportError as e:
    print(f"Warning: Route modules not found or import error: {e}")
    restaurant_bp = None
    menu_bp = None
    order_bp = None
    default_bp = None
    
try:
    from UGC.ugc_routes import ugc_bp
except ImportError as e:
    print(f"UGC Route import failed: {e}")
    ugc_bp = None

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = safe_getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = safe_getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_AS_ASCII'] = False
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'video')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ADMIN_USERNAME = safe_getenv('ADMIN_USER')
ADMIN_PASSWORD_HASH = generate_password_hash(safe_getenv('ADMIN_PASS'))
FRONTEND_URL = safe_getenv('FRONTEND_URL')

db.init_app(app)

# 註冊 Blueprints
app.register_blueprint(auth_bp)

if restaurant_bp:
    app.register_blueprint(restaurant_bp, url_prefix='/api/restaurants')
if menu_bp:
    app.register_blueprint(menu_bp, url_prefix='/api/menus')
if order_bp:
    app.register_blueprint(order_bp, url_prefix='/api/orders')
if default_bp:
    app.register_blueprint(default_bp)
if ugc_bp:
    app.register_blueprint(ugc_bp, url_prefix='/api/videos')

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

admin = Admin(app, name='e-system-delivery 的後台', index_view=MyAdminIndexView(name='首頁'))
admin.add_view(AdminModelView(User, db.session, name='使用者管理'))
admin.add_view(AdminModelView(Log, db.session, name='日誌紀錄'))
admin.add_view(AdminModelView(OAuthState, db.session, name='OAuth 狀態'))

with app.app_context():
    db.create_all()

def get_speech_client():
    creds_json = os.environ.get('GOOGLE_STT')
    if creds_json:
        creds_dict = json.loads(creds_json)
        credentials = service_account.Credentials.from_service_account_info(creds_dict)
        return speech.SpeechClient(credentials=credentials)
    return speech.SpeechClient()

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
        
        subprocess.run(['ffmpeg', '-y', '-i', temp_input_path, '-ar', '16000', '-ac', '1', '-c:a', 'pcm_s16le', temp_wav_path], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        with open(temp_wav_path, "rb") as wav_file:
            converted_content = wav_file.read()

        client = get_speech_client()
        audio = speech.RecognitionAudio(content=converted_content)
        config = speech.RecognitionConfig(language_code="zh-TW", enable_automatic_punctuation=True, encoding=speech.RecognitionConfig.AudioEncoding.LINEAR16, sample_rate_hertz=16000, audio_channel_count=1)
        response = client.recognize(config=config, audio=audio)
        text = "".join([result.alternatives[0].transcript for result in response.results])
        return jsonify({"text": text}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if temp_input_path and os.path.exists(temp_input_path): os.remove(temp_input_path)
        if temp_wav_path and os.path.exists(temp_wav_path): os.remove(temp_wav_path)

@app.route('/api/ai/stt/mock', methods=['POST'])
def mock_stt():
    time.sleep(random.uniform(1.0, 2.5))
    return jsonify({"text": random.choice(["這是一個測試回應，你的麥克風運作正常！", "我聽到了，但我是假的 AI。"])})

@app.route('/api/ai/recommend', methods=['POST'])
def recommend_restaurants():
    data = request.get_json()
    user_input = data.get('user_input', '')
    tags_str = ", ".join(data.get('user_tags', []))
    time.sleep(1.5)
    return jsonify({
        "status": "success",
        "data": {
            "user_intent_analysis": f"偵測到你想吃：{user_input} (偏好: {tags_str})",
            "recommendations": [
                {"id": 101, "name": "健康輕食餐盒", "description": "低油低鹽", "image_url": "https://placehold.co/600x400", "tags": ["健康"], "rating": 4.8, "delivery_time": "25-35 min"},
                {"id": 102, "name": "日式清爽烏龍麵", "description": "柴魚高湯", "image_url": "https://placehold.co/600x400", "tags": ["日式"], "rating": 4.5, "delivery_time": "30-40 min"}
            ]
        }
    }), 200

@app.route('/api/pay')
def pay():
    return jsonify({'message': '付款成功', 'order_id': request.get_json().get('order_id'), "status": "Paid"}), 200

@app.route('/api/ai/merchant/consultant', methods=['POST'])
@token_required
def merchant_consultant(current_user):
    time.sleep(2)
    return jsonify({
        "status": "success",
        "data": {
            "market_warning": {"level": "紅色警報", "title": "市場競爭高", "content": "周邊競品多..."},
            "menu_suggestion": {"title": "差異化策略", "new_dish_ideas": [{"name": "剝皮辣椒雞", "reason": "熱門"}], "improvement_action": "改善包材"}
        }
    }), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000)) 
    print(f"Starting Flask development server on http://127.0.0.1:{port}...")
    app.run(host='0.0.0.0', port=port)