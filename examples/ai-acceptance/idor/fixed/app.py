"""Synthetic tenant-isolated object lookup fixture."""

ORDERS = {
    "order-1": {"tenant_id": "tenant-a", "description": "Synthetic order A"},
    "order-2": {"tenant_id": "tenant-b", "description": "Synthetic order B"},
}


def get_order(requesting_tenant: str, order_id: str) -> dict[str, str]:
    order = ORDERS.get(order_id)
    if order is None or order["tenant_id"] != requesting_tenant:
        raise LookupError("Order not found")
    return order
