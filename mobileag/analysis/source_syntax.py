"""Small lexical helpers for candidate review, not a Java/Kotlin AST or proof engine."""
from __future__ import annotations

import re
from dataclasses import dataclass

from mobileag.analysis.android_surface import mask_non_code


@dataclass(frozen=True)
class CallSite:
    operation: str
    offset: int
    end: int
    args: tuple[str, ...]
    code_args: tuple[str, ...]


def call_sites(source: str, pattern: str):
    """Yield balanced calls, keeping commas in nested calls/arrays/literals intact.

    The caller supplies an operation regex, without an opening parenthesis.
    Comments/literals cannot invent operations. Unbalanced calls are ignored.
    Generic type argument commas and expression-bodied methods are not resolved.
    """
    code = mask_non_code(source)
    for match in re.finditer(pattern + r"\s*\(", code):
        start = match.end()
        stack = [")"]
        boundaries = [start]
        pos = start
        while pos < len(code) and stack:
            char = code[pos]
            if char in "([{":
                stack.append({"(": ")", "[": "]", "{": "}"}[char])
            elif char in ")]}":
                if char != stack[-1]:
                    break
                stack.pop()
            elif char == "," and len(stack) == 1:
                boundaries.extend([pos, pos + 1])
            pos += 1
        if stack:
            continue
        boundaries.append(pos - 1)
        pairs = list(zip(boundaries[::2], boundaries[1::2]))
        if len(pairs) == 1 and not code[start:pos - 1].strip():
            pairs = []
        yield CallSite(
            code[match.start():start - 1].strip(), match.start(), pos,
            tuple(source[a:b].strip() for a, b in pairs),
            tuple(code[a:b].strip() for a, b in pairs),
        )


def literal_flag_bits(expression: str, symbols: dict[str, int]) -> tuple[int, bool]:
    """Resolve ONLY literal/symbolic bitwise ORs. Never eval uploaded source.

    Known bits are retained when another operand is unknown; completeness is
    False for variables, function calls, arithmetic, casts or unsupported syntax.
    """
    bits = 0
    complete = True
    for operand in expression.split("|"):
        token = operand.strip().strip("()").strip()
        name = token.rsplit(".", 1)[-1]
        if name in symbols and re.fullmatch(r"[\w.]+", token):
            bits |= symbols[name]
        elif re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|0|[1-9]\d*)[lL]?", token):
            number = token.rstrip("lL")
            bits |= int(number, 16 if number.lower().startswith("0x") else 10)
        else:
            complete = False
    return bits, complete
