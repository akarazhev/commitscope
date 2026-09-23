"""Synthetic tenant-isolated object lookup fixture."""

import hashlib
import hmac
import os


ORDERS = {
    "order-1": {"tenant_id": "tenant-a", "description": "Synthetic order A"},
    "order-2": {"tenant_id": "tenant-b", "description": "Synthetic order B"},
}


def authenticated_tenant(session_token: str) -> str:
    """Verify a tenant assertion issued after login by the trusted auth service."""
    signing_key = os.environ.get("SYNTHETIC_IDOR_SESSION_SIGNING_KEY")
    if not signing_key:
        raise RuntimeError("Session signing key is not configured")
    tenant_id, separator, signature = session_token.rpartition(".")
    if not separator or not tenant_id or not signature:
        raise PermissionError("Invalid session")
    expected = hmac.new(
        signing_key.encode("utf-8"), tenant_id.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise PermissionError("Invalid session")
    return tenant_id


def get_order(session_token: str, order_id: str) -> dict[str, str]:
    requesting_tenant = authenticated_tenant(session_token)
    order = ORDERS.get(order_id)
    if order is None or order["tenant_id"] != requesting_tenant:
        raise LookupError("Order not found")
    return order
