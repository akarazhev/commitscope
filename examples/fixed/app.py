"""Remediated LOCAL fixture. Parameters model identity, not real authentication."""
import ast
import json
import operator
import subprocess
import sys

INVOICES = {
    '1': {'id': '1', 'tenant': 'tenant-a', 'amount': 100},
    '2': {'id': '2', 'tenant': 'tenant-b', 'amount': 200},
}

def read_invoice(tenant, invoice_id):
    item = INVOICES.get(str(invoice_id))
    if item is None or item['tenant'] != tenant:
        raise PermissionError('Invoice is unavailable to this tenant')
    return dict(item)

def calculate_total(expression):
    if not isinstance(expression, str) or len(expression) > 128:
        raise ValueError('Expression must be a short arithmetic string')
    try:
        tree = ast.parse(expression, mode='eval')
    except (SyntaxError, ValueError) as exc:
        raise ValueError('Invalid arithmetic expression') from exc
    if sum(1 for _ in ast.walk(tree)) > 40:
        raise ValueError('Expression is too complex')
    allowed = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul}
    def calculate(node):
        if isinstance(node, ast.Constant) and type(node.value) is int and abs(node.value) <= 1000000:
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in allowed:
            value = allowed[type(node.op)](calculate(node.left), calculate(node.right))
            if abs(value) > 1000000000:
                raise ValueError('Result exceeds the demo limit')
            return value
        raise ValueError('Only bounded integers, addition, subtraction and multiplication are supported')
    return calculate(tree.body)

def run_diagnostic(name):
    commands = {'python-version': [sys.executable, '--version']}
    if name not in commands:
        raise ValueError('Unknown diagnostic')
    return subprocess.run(commands[name], shell=False, capture_output=True, text=True, timeout=5)

if __name__ == '__main__':
    print(json.dumps(read_invoice('tenant-a', '1')))
