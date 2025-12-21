from flask import Blueprint, Response
from app.services.restaurant_service import get_restaurant_list, get_restaurant_by_id

restaurant_bp = Blueprint("restaurant", __name__, url_prefix="/api/restaurant")

@restaurant_bp.route("/", methods=["GET"])
def list_restaurants():
    return Response(get_restaurant_list(), mimetype="application/json")

@restaurant_bp.route("/<int:restaurant_id>", methods=["GET"])
def get_restaurant(restaurant_id):
    return Response(get_restaurant_by_id(restaurant_id), mimetype="application/json")