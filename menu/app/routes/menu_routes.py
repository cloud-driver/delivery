from flask import Blueprint, jsonify, request
from app.services.menu_service import get_menu_by_restaurant_id

menu_bp = Blueprint("menu", __name__, url_prefix="/api")

@menu_bp.route("/menu/<restaurant_id>", methods=["GET"])
def get_menu(restaurant_id):
    menu_data = get_menu_by_restaurant_id(restaurant_id)
    return jsonify(menu_data)

@menu_bp.route("/menu", methods=["POST"])
def create_menu():
    data = request.get_json()
    # TODO: 呼叫 menu_service 來新增菜單
    return jsonify({"message": "菜單已新增"}), 201

@menu_bp.route("/menu/<menu_id>", methods=["PUT"])
def update_menu(menu_id):
    data = request.get_json()
    # TODO: 呼叫 menu_service 來更新菜單
    return jsonify({"message": "菜單已更新"})

@menu_bp.route("/menu/<menu_id>", methods=["DELETE"])
def delete_menu(menu_id):
    # TODO: 呼叫 menu_service 來刪除菜單
    return jsonify({"message": "菜單已刪除"})