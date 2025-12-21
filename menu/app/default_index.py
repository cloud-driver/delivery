from flask import Blueprint, jsonify

default_bp = Blueprint("default", __name__)

@default_bp.route("/", methods=["GET"])
def index():
    """
    後端初始狀態檢查
    """
    return jsonify({
        "status": "ok",
        "message": "後端 API 正常運作中",
        "version": "1.0.0"
    })