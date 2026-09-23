"""Synthetic untrusted-eval fixture. Never deploy this code."""


def calculate(expression: str):
    return eval(expression)
