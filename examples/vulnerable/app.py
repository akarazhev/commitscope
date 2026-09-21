"""Intentionally vulnerable LOCAL demonstration. Never deploy this module."""
import json
import subprocess

INVOICES = {
    '1': {'id': '1', 'tenant': 'tenant-a', 'amount': 100},
    '2': {'id': '2', 'tenant': 'tenant-b', 'amount': 200},
}

def read_invoice(tenant, invoice_id):
    # BUG: the tenant argument is not used for authorization.
    return dict(INVOICES[str(invoice_id)])

def calculate_total(expression):
    # BUG: evaluating untrusted expressions is not a safe calculator.
    return eval(expression)

def run_diagnostic(command):
    # BUG: a caller-controlled shell command is not an acceptable diagnostic API.
    return subprocess.run(command, shell=True, capture_output=True, text=True)

if __name__ == '__main__':
    print(json.dumps(read_invoice('tenant-a', '1')))
