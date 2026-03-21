#!/usr/bin/env python3
"""Inline FDP call results from a trace log into C/C++ source using tree-sitter.

This replaces supported fdp.* call expressions with concrete literals from trace,
which makes minimized harnesses easier to read.
"""

from __future__ import annotations

import argparse
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque

from tree_sitter import Language, Node, Parser
import tree_sitter_cpp as ts_cpp

SUPPORTED = {
    "ConsumeBytes",
    "ConsumeBytesWithTerminator",
    "ConsumeRemainingBytes",
    "ConsumeBytesAsString",
    "ConsumeRandomLengthString",
    "ConsumeRemainingBytesAsString",
    "ConsumeIntegral",
    "ConsumeIntegralInRange",
    "ConsumeFloatingPoint",
    "ConsumeFloatingPointInRange",
    "ConsumeProbability",
    "ConsumeBool",
    "ConsumeEnum",
    "PickValueInArray",
    "ConsumeData",
    "remaining_bytes",
}

CPP_LANGUAGE = Language(ts_cpp.language())
PARSER = Parser(CPP_LANGUAGE)


@dataclass
class CallSite:
    start: int
    end: int
    method: str
    key: int | None
    fallback_keys: list[int]


def _iter_nodes(root: Node) -> list[Node]:
    out: list[Node] = []
    stack = [root]
    while stack:
        n = stack.pop()
        out.append(n)
        for c in reversed(n.children):
            stack.append(c)
    return out


def _text(src: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def _method_name(field: Node, src: bytes) -> str:
    if field.type == "field_identifier":
        return _text(src, field)
    if field.type == "template_method":
        for ch in field.children:
            if ch.type == "field_identifier":
                return _text(src, ch)
    return ""


def _parse_int_literal(token: str) -> int | None:
    t = token.strip()
    if not t:
        return None
    if t.startswith("+"):
        t = t[1:]
    # int(x, 0) supports decimal/hex/octal prefixes.
    try:
        return int(t, 0)
    except ValueError:
        return None


def _extract_explicit_id(args_node: Node, src: bytes) -> int | None:
    # If the last argument is an integer literal, treat it as explicit FDP site id.
    arg_nodes = [c for c in args_node.named_children]
    if not arg_nodes:
        return None
    last = arg_nodes[-1]
    if last.type not in {"number_literal", "unary_expression"}:
        return None
    return _parse_int_literal(_text(src, last))


def _default_site_id_candidates(call_node: Node, field_node: Node | None) -> list[int]:
    # Mirror FDP default: ((__builtin_LINE() << 12) ^ __builtin_COLUMN())
    # Column base may differ by compiler; try both 1-based and 0-based fallback.
    row0, col0 = call_node.start_point
    if field_node is not None:
        _, col_field = field_node.start_point
        col0 = col_field
    line = row0 + 1
    return [((line << 12) ^ (col0 + 1)), ((line << 12) ^ col0), line]


def _find_fdp_calls(source: str) -> list[CallSite]:
    src_bytes = source.encode("utf-8")
    tree = PARSER.parse(src_bytes)
    calls: list[CallSite] = []

    for node in _iter_nodes(tree.root_node):
        if node.type != "call_expression":
            continue

        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "field_expression":
            continue

        recv = fn.child_by_field_name("argument")
        field = fn.child_by_field_name("field")
        if _text(src_bytes, recv).strip() != "fdp" or field is None:
            continue

        method = _method_name(field, src_bytes)
        if method not in SUPPORTED:
            continue

        args = node.child_by_field_name("arguments")
        if args is None:
            continue

        key = _extract_explicit_id(args, src_bytes)
        fallback_keys = []
        if key is None:
            fallback_keys = _default_site_id_candidates(node, field)
            if fallback_keys:
                key = fallback_keys[0]

        calls.append(
            CallSite(
                start=node.start_byte,
                end=node.end_byte,
                method=method,
                key=key,
                fallback_keys=fallback_keys,
            )
        )

    return calls


def _load_trace(trace_path: Path) -> dict[int, Deque[tuple[str, any]]]:
    streams = defaultdict(deque)
    for line in trace_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.strip().split()
        if not len(parts):
            continue
        try:
            key = int(parts[1], 0)
        except (ValueError, IndexError):
            continue
            
        if parts[0] == "S":
            val = float(parts[2])
            if val.is_integer():
                val = int(val)
            streams[key].append(("S", val))
        elif parts[0] == "R":
            streams[key].append(("R", int(parts[2], 0)))
        elif parts[0] == "B":
            count = int(parts[2], 0)
            bytes_list = []
            for i in range(count):
                if 3 + i < len(parts):
                    bytes_list.append(int(parts[3 + i]))
                else:
                    bytes_list.append(0)
            streams[key].append(("B", bytes_list))
    return streams


def inline_source(source: str, streams: dict[int, Deque[tuple[str, any]]]) -> tuple[str, int]:
    calls = _find_fdp_calls(source)
    if not calls:
        return source, 0

    replacements: list[tuple[int, int, str]] = []
    replaced = 0

    for call in calls:
        record = None
        if call.key is not None and call.key in streams and streams[call.key]:
            record = streams[call.key].popleft()
        else:
            for candidate in call.fallback_keys:
                if candidate in streams and streams[candidate]:
                    record = streams[candidate].popleft()
                    break

        if record is None:
            continue

        rtype, val = record
        
        literal = ""
        if call.method == "ConsumeBool":
            literal = "true" if val != 0 else "false"
        elif call.method in ("ConsumeBytesAsString", "ConsumeRandomLengthString", "ConsumeRemainingBytesAsString"):
            if rtype == "B":
                hex_str = "".join(f"\\x{b:02x}" for b in val)
                if not hex_str: hex_str = ""
                literal = f'std::string("{hex_str}", {len(val)})'
            elif rtype == "R":
                literal = 'std::string("")'
            else:
                literal = 'std::string("")'
        elif call.method in ("ConsumeBytes", "ConsumeBytesWithTerminator", "ConsumeRemainingBytes"):
            if rtype == "B":
                hex_list = ", ".join(f"0x{b:02x}" for b in val)
                literal = f"{{{hex_list}}}"
            else:
                literal = "{}"
        elif call.method == "ConsumeData":
            if rtype == "B":
                literal = str(len(val))
            else:
                literal = "0"
        elif call.method == "remaining_bytes":
            if rtype == "R":
                literal = str(val)
            else:
                literal = str(val) if isinstance(val, int) else "0"
        else:
            literal = str(val)

        replacements.append((call.start, call.end, literal))
        replaced += 1

    if not replacements:
        return source, 0

    # Apply from back to front.
    out = source
    for start, end, literal in sorted(replacements, key=lambda x: x[0], reverse=True):
        out = out[:start] + literal + out[end:]

    return out, replaced


def main() -> None:
    parser = argparse.ArgumentParser(description="Inline FDP scalar calls from trace")
    parser.add_argument("--input", required=True, help="Input C/C++ file")
    parser.add_argument("--trace", required=True, help="Trace log produced by FDP dump mode")
    parser.add_argument("--output", required=True, help="Output C/C++ file")
    args = parser.parse_args()

    src = Path(args.input).read_text(encoding="utf-8", errors="ignore")
    streams = _load_trace(Path(args.trace))
    transformed, count = inline_source(src, streams)
    Path(args.output).write_text(transformed, encoding="utf-8")
    print(f"Inlined {count} FDP calls into {args.output}")


if __name__ == "__main__":
    main()
