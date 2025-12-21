from sqlalchemy import create_engine, MetaData, Table, insert, select, update
from sqlalchemy.orm import Session
from datetime import datetime
import os
import logging
from typing import Any, Dict, List, Optional

def _load_db_url_from_file() -> Optional[str]:
    """Try to read the DB URL from data/db_link if present."""
    from pathlib import Path

    try:
        repo_root = Path(__file__).resolve().parents[3]
        link_file = repo_root / "data" / "db_link"
        if link_file.exists():
            return link_file.read_text(encoding="utf-8").strip()
    except Exception:
        pass
    return None


SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or _load_db_url_from_file() or (
    "mysql+pymysql://root:@127.0.0.1:3306/e-system-delivery?charset=utf8mb4"
)

logger = logging.getLogger(__name__)

engine = create_engine(SQLALCHEMY_DATABASE_URI, echo=False)
metadata = MetaData()

# try to autoload tables; fall back to in-memory store if DB is unavailable
orders_table: Optional[Table] = None
order_items_table: Optional[Table] = None
_inmem_orders: Dict[int, Dict[str, Any]] = {}
_inmem_items: Dict[int, List[Dict[str, Any]]] = {}
_inmem_next_id = 1

try:
    orders_table = Table("orders", metadata, autoload_with=engine)
    order_items_table = Table("order_items", metadata, autoload_with=engine)
except Exception:
    orders_table = None
    order_items_table = None

# import services lazily where needed to avoid circular imports
def _get_realtime_service():
    from app.services import realtime_service

    return realtime_service


def _get_notification_service():
    from app.services import notification_service

    return notification_service

def calculate_total(data: Dict[str, Any]) -> float:
    """Compute the total amount for an order payload.

    Expects payload['items'] to be an iterable of dicts with `price` and
    optional `quantity` keys.
    """
    total = 0.0
    for item in data.get("items", []):
        price = float(item.get("price", 0))
        qty = int(item.get("quantity", 1))
        total += price * qty
    return total

def save_order_to_db(data: Dict[str, Any]) -> int:
    """Save an order and its items to the DB or in-memory store.

    Returns the created order id.
    """
    global _inmem_next_id

    if orders_table is not None and order_items_table is not None:
        with Session(engine) as session:
            try:
                stmt = insert(orders_table).values(
                    restaurant_id=data["restaurant_id"],
                    table_id=data.get("table_id"),
                    note=data.get("note", ""),
                    status="pending",
                    total_amount=calculate_total(data),
                    payment_method=data.get("payment_method", "credit_card"),
                    payment_status="unpaid",
                    created_at=datetime.now(),
                    updated_at=datetime.now(),
                )
                result = session.execute(stmt)
                order_id = int(result.inserted_primary_key[0])

                for item in data.get("items", []):
                    item_stmt = insert(order_items_table).values(
                        order_id=order_id,
                        dish_id=item["dish_id"],
                        name=item.get("name"),
                        quantity=item.get("quantity", 1),
                        price=item.get("price", 0),
                    )
                    session.execute(item_stmt)

                session.commit()
                return order_id
            except Exception:
                session.rollback()
                logger.exception("Failed to save order to DB")
                raise

    # fallback: in-memory store for development
    order_id = _inmem_next_id
    _inmem_next_id += 1
    now = datetime.now().isoformat()
    _inmem_orders[order_id] = {
        "order_id": order_id,
        "restaurant_id": data.get("restaurant_id"),
        "table_id": data.get("table_id"),
        "note": data.get("note", ""),
        "status": "pending",
        "created_at": now,
        "updated_at": now,
        "total_amount": float(calculate_total(data)),
        "payment": {"method": data.get("payment_method", "credit_card"), "status": "unpaid"},
    }
    _inmem_items[order_id] = [
        {
            "dish_id": item.get("dish_id"),
            "name": item.get("name"),
            "quantity": item.get("quantity", 1),
            "price": float(item.get("price", 0)),
        }
        for item in data.get("items", [])
    ]
    return order_id

def get_order_by_id(order_id: int) -> Optional[Dict[str, Any]]:
    """Return a combined order dict with items, or None if not found."""
    if orders_table is not None and order_items_table is not None:
        with engine.connect() as conn:
            stmt = select(orders_table).where(orders_table.c.order_id == order_id)
            order = conn.execute(stmt).mappings().first()
            if not order:
                return None

            item_stmt = select(order_items_table).where(order_items_table.c.order_id == order_id)
            items = conn.execute(item_stmt).mappings().all()

            return {
                "order_id": order["order_id"],
                "restaurant_id": order["restaurant_id"],
                "table_id": order["table_id"],
                "note": order["note"],
                "status": order["status"],
                "created_at": order["created_at"].isoformat(),
                "updated_at": order["updated_at"].isoformat(),
                "total_amount": float(order["total_amount"]),
                "payment": {"method": order["payment_method"], "status": order["payment_status"]},
                "items": [
                    {
                        "dish_id": item["dish_id"],
                        "name": item["name"],
                        "quantity": item["quantity"],
                        "price": float(item["price"]),
                    }
                    for item in items
                ],
            }

    # in-memory fallback
    o = _inmem_orders.get(order_id)
    if not o:
        return None
    return {
        "order_id": o["order_id"],
        "restaurant_id": o["restaurant_id"],
        "table_id": o.get("table_id"),
        "note": o.get("note"),
        "status": o.get("status"),
        "created_at": o.get("created_at"),
        "updated_at": o.get("updated_at"),
        "total_amount": o.get("total_amount"),
        "payment": o.get("payment"),
        "items": _inmem_items.get(order_id, []),
    }

def update_order_status_in_db(order_id: int, new_status: str) -> bool:
    """Update the order status and trigger notifications.

    This function centralizes SSE publishing and calling the notification
    service so callers don't need to duplicate that logic.
    """
    realtime = _get_realtime_service()
    notifications = _get_notification_service()

    if orders_table is not None:
        with Session(engine) as session:
            try:
                stmt = (
                    update(orders_table)
                    .where(orders_table.c.order_id == order_id)
                    .values(status=new_status, updated_at=datetime.now())
                )
                result = session.execute(stmt)
                session.commit()
                updated = result.rowcount > 0
                if updated:
                    order = get_order_by_id(order_id)
                    try:
                        restaurant_id = (order or {}).get("restaurant_id")
                        if restaurant_id:
                            realtime.publish(
                                restaurant_id,
                                {"type": "order_status_updated", "order": order},
                                event="order_update",
                            )
                    except Exception:
                        logger.exception("Failed to publish order_update SSE")

                    try:
                        notifications.notify_restaurant(order_id, order)
                    except Exception:
                        logger.exception("notify_restaurant failed")

                return updated
            except Exception:
                session.rollback()
                logger.exception("Failed to update order status in DB")
                raise

    # in-memory fallback path
    o = _inmem_orders.get(order_id)
    if not o:
        return False
    o["status"] = new_status
    o["updated_at"] = datetime.now().isoformat()

    try:
        order = get_order_by_id(order_id)
        restaurant_id = (order or {}).get("restaurant_id")
        if restaurant_id:
            _get_realtime_service().publish(
                restaurant_id, {"type": "order_status_updated", "order": order}, event="order_update"
            )
    except Exception:
        logger.exception("Failed to publish in-memory order_update SSE")

    try:
        _get_notification_service().notify_restaurant(order_id, order)
    except Exception:
        logger.exception("notify_restaurant failed (in-memory)")

    return True

def cancel_order_in_db(order_id):
    """取消訂單"""
    return update_order_status_in_db(order_id, "cancelled")

def notify_payment_system(order_id: int, data: Any) -> None:
    """Trigger payment notification in background (non-blocking)."""
    try:
        notif = _get_notification_service()
        # submit to background executor; do not wait
        if hasattr(notif, "notify_payment_system_async"):
            notif.notify_payment_system_async(order_id, data)
        else:
            # fallback to direct call
            notif.notify_payment_system(order_id, data)
    except Exception:
        logger.exception("notify_payment_system failed")


def notify_restaurant(order_id: int, data: Any) -> None:
    """Trigger restaurant notification in background (non-blocking)."""
    try:
        notif = _get_notification_service()
        if hasattr(notif, "notify_restaurant_async"):
            notif.notify_restaurant_async(order_id, data)
        else:
            notif.notify_restaurant(order_id, data)
    except Exception:
        logger.exception("notify_restaurant failed")