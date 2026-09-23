"""Synthetic arithmetic parser that rejects executable expressions."""
import ast
import math
import operator


OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}
MAX_AST_DEPTH = 32


def _require_finite(value):
    if type(value) is float and not math.isfinite(value):
        raise ValueError("Only finite arithmetic is allowed")
    return value


def _evaluate(node, depth=0):
    if depth > MAX_AST_DEPTH:
        raise ValueError("Expression is too deep")
    if isinstance(node, ast.Expression):
        return _evaluate(node.body, depth + 1)
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return _require_finite(node.value)
    if isinstance(node, ast.BinOp) and type(node.op) in OPERATORS:
        return _require_finite(
            OPERATORS[type(node.op)](
                _evaluate(node.left, depth + 1), _evaluate(node.right, depth + 1)
            )
        )
    raise ValueError("Only numeric arithmetic is allowed")


def calculate(expression: str):
    if len(expression) > 200:
        raise ValueError("Expression is too long")
    if "\x00" in expression:
        raise ValueError("Invalid arithmetic expression")
    try:
        return _evaluate(ast.parse(expression, mode="eval"))
    except (SyntaxError, UnicodeEncodeError, ZeroDivisionError) as error:
        raise ValueError("Invalid arithmetic expression") from error
