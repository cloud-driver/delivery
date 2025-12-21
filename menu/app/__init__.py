from flask import Flask
from app.routes.restaurant_routes import restaurant_bp
from app.routes.menu_routes import menu_bp
from app.routes.order_routes import order_bp
from app.default_index import default_bp
def create_app():
    app = Flask(__name__)

    # 註冊 Blueprint
    app.register_blueprint(restaurant_bp)
    app.register_blueprint(menu_bp)
    app.register_blueprint(order_bp)
    app.register_blueprint(default_bp)

    return app