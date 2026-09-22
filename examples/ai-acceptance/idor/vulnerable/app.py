"""Synthetic cross-tenant IDOR fixture. Never deploy this code."""

ORDERS = {
    "order-1": {"tenant_id": "tenant-a", "description": "Synthetic order A"},
    "order-2": {"tenant_id": "tenant-b", "description": "Synthetic order B"},
}


def get_order(requesting_tenant: str, order_id: str) -> dict[str, str]:
    del requesting_tenant
    return ORDERS[order_id]
