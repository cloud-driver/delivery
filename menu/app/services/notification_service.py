"""Notification helpers (demo implementations).

In a real system these should call external services (push, email, SMS)
or enqueue background tasks. The functions here are simple and use
logging so they can be tested locally without external dependencies.
"""

from typing import Any
import logging

logger = logging.getLogger(__name__)


def send_push_notification(target: str, message: str) -> None:
	"""Send a push notification (demo: log the message)."""
	logger.info("PUSH -> %s: %s", target, message)


def send_email(recipient: str, subject: str, body: str) -> None:
	"""Send an email (demo: log the message)."""
	logger.info("EMAIL -> %s | %s | %s", recipient, subject, body)


def send_sms(phone_number: str, message: str) -> None:
	"""Send an SMS (demo: log the message)."""
	logger.info("SMS -> %s: %s", phone_number, message)


def notify_payment_system(order_id: int, data: Any) -> None:
	"""Notify payment system about a created order (demo).

	This function is intentionally simple. In production it should
	call the payment provider API asynchronously and handle retries.
	"""
	message = f"訂單 {order_id} 已建立，金額：{data.get('total_amount') if isinstance(data, dict) else 'unknown'}"
	send_push_notification("payment-system", message)


def notify_restaurant(order_id: int, data: Any) -> None:
	"""Notify restaurant of a new order (demo).

	Replace the body of this function with real integrations or
	enqueue a background job for sending email/SMS/push.
	"""
	subject = f"新訂單通知 #{order_id}"
	body = f"餐廳收到新訂單：{data}"
	send_email("restaurant@example.com", subject, body)
	send_sms("0912345678", body)


# Background executor for non-blocking notification delivery.
from concurrent.futures import ThreadPoolExecutor, Future
_executor = ThreadPoolExecutor(max_workers=4)


def _submit(fn, *args, **kwargs) -> Future:
	try:
		return _executor.submit(fn, *args, **kwargs)
	except Exception:
		logger.exception("Failed to submit background task")
		raise


def notify_payment_system_async(order_id: int, data: Any) -> Future:
	"""Submit payment notification to background executor."""
	return _submit(notify_payment_system, order_id, data)


def notify_restaurant_async(order_id: int, data: Any) -> Future:
	"""Submit restaurant notification to background executor."""
	return _submit(notify_restaurant, order_id, data)
