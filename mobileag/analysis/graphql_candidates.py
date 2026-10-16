"""Bounded lexical helpers for GraphQL operation-name candidates."""
from __future__ import annotations

import re


GRAPHQL_OPERATION_PATTERN = re.compile(
    r"\b(query|mutation|subscription)\b(?:\s+([_A-Za-z][_0-9A-Za-z]{0,127}))?\s*(?=\(|\{)"
)


def mask_graphql_non_code(source: str) -> tuple[str, bool]:
    """Blank GraphQL comments and string values while preserving lines and operation syntax."""
    chars = list(source)
    index = 0
    malformed_string = False

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if chars[position] not in "\r\n":
                chars[position] = " "

    while index < len(source):
        if source[index] == "#":
            end = index + 1
            while end < len(source) and source[end] not in "\r\n":
                end += 1
            blank(index, end)
            index = end
            continue
        if source.startswith('"""', index):
            start = index
            index += 3
            while index < len(source):
                if source.startswith('\\"""', index):
                    index += 4
                elif source.startswith('"""', index):
                    index += 3
                    break
                else:
                    index += 1
            else:
                malformed_string = True
            blank(start, index)
            continue
        if source[index] == '"':
            start = index
            index += 1
            closed = False
            while index < len(source) and source[index] not in "\r\n":
                if source[index] == "\\":
                    index += 2
                elif source[index] == '"':
                    index += 1
                    closed = True
                    break
                else:
                    index += 1
            if not closed:
                malformed_string = True
            blank(start, index)
            continue
        index += 1
    return "".join(chars), malformed_string


def extract_graphql_operation_candidates(
    document: str, *, max_candidates: int = 100,
) -> tuple[list[dict[str, str | None]], bool, bool]:
    """Return operation type/name candidates, malformed-string state, and truncation state."""
    masked, malformed = mask_graphql_non_code(document)
    candidates: list[dict[str, str | None]] = []
    truncated = False
    seen: set[tuple[str, str | None]] = set()
    depth = 0
    index = 0
    while index < len(masked):
        # GraphQL operations are document definitions at the root level. A
        # field named `query`, `mutation`, or `subscription` inside a selection
        # set must not be mistaken for a second operation declaration.
        if depth == 0:
            match = GRAPHQL_OPERATION_PATTERN.match(masked, index)
            if match:
                operation_type = match.group(1).lower()
                operation_name = match.group(2)
                key = (operation_type, operation_name)
                if key not in seen:
                    if len(candidates) >= max_candidates:
                        truncated = True
                        break
                    seen.add(key)
                    candidates.append({"operation_type": operation_type, "operation_name": operation_name})
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth = max(0, depth - 1)
        index += 1
    return candidates, malformed, truncated
