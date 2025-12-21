from typing import Any, Dict, Optional
import logging

from flask import Blueprint, jsonify, request, Response, stream_with_context
from app.services.order_service import (
    save_order_to_db,
    get_order_by_id,
    update_order_status_in_db,
    notify_payment_system,
    notify_restaurant,
)
from app.services import realtime_service

logger = logging.getLogger(__name__)

order_bp = Blueprint("order", __name__, url_prefix="/api")


def not_found(msg: str = "訂單不存在"):
    """Return a 404 JSON response with a friendly message."""
    return jsonify({"error": msg}), 404


@order_bp.route("/order", methods=["POST"])
def create_order() -> Any:
    """Create a new order.

    Request JSON must include `restaurant_id` and `items`.
    Returns the created order and a friendly message.
    """
    payload: Optional[Dict[str, Any]] = request.get_json()
    if not payload:
        return jsonify({"error": "缺少訂單資料"}), 400

    order_id = save_order_to_db(payload)

    # trigger synchronous payment and restaurant notifications (demo)
    try:
        notify_payment_system(order_id, payload)
    except Exception as exc:  # pragma: no cover - external integration
        logger.exception("notify_payment_system failed: %s", exc)

    try:
        notify_restaurant(order_id, payload)
    except Exception as exc:  # pragma: no cover - external integration
        logger.exception("notify_restaurant failed: %s", exc)

    order = get_order_by_id(order_id)

    # publish SSE so subscribers receive the new-order event
    try:
        restaurant_id = (order or {}).get("restaurant_id") or payload.get("restaurant_id")
        realtime_service.publish(
            restaurant_id,
            {"type": "order_created", "order": order, "message": "訂單已送出"},
            event="order_created",
        )
    except Exception as exc:
        logger.debug("SSE publish (order_created) failed: %s", exc)

    result = (order.copy() if isinstance(order, dict) else {"order": order})
    result["message"] = "訂單已送出"
    return jsonify(result), 201

@order_bp.route("/order/<int:order_id>", methods=["GET"])
def get_order(order_id: int) -> Any:
    order = get_order_by_id(order_id)
    return jsonify(order) if order else not_found()

@order_bp.route("/order/<int:order_id>/status", methods=["PUT"])
def update_order_status(order_id: int) -> Any:
    data = request.get_json() or {}
    new_status = data.get("status")
    if not new_status:
        return jsonify({"error": "缺少狀態"}), 400

    updated = update_order_status_in_db(order_id, new_status)
    if updated:
        order = get_order_by_id(order_id)
        return jsonify(order), 200
    return not_found()


@order_bp.route('/notifications/stream/<restaurant_id>')
def notifications_stream(restaurant_id: str) -> Response:
    """Server-Sent Events endpoint for a restaurant's realtime channel.

    Example: EventSource('/api/notifications/stream/R002')
    """

    def generator():
        yield from realtime_service.subscribe(restaurant_id)

    headers = {
        "Cache-Control": "no-cache",
        "Content-Type": "text/event-stream",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }

    return Response(stream_with_context(generator()), headers=headers)

@order_bp.route("/order/<int:order_id>", methods=["DELETE"])
def cancel_order(order_id: int) -> Any:
    cancelled = update_order_status_in_db(order_id, "cancelled")
    if cancelled:
        order = get_order_by_id(order_id)
        return jsonify(order), 200
    return not_found()