#!/usr/bin/env python3
"""Inject stable numeric callsite IDs into fdp.* calls.

This solves replay desync when:
1) multiple fdp calls exist on the same source line
2) line numbers shift during C-Reduce rewrites

Supported APIs:
- fdp.ConsumeIntegral<...>(...)
- fdp.ConsumeIntegralInRange<...>(...)
- fdp.ConsumeBytes<...>(...)
- fdp.ConsumeBool(...)
- fdp.remaining_bytes(...)
"""

from __future__ import annotations

import argparse
import sys
import warnings

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

warnings.simplefilter("ignore", category=FutureWarning)

CPP_LANGUAGE = Language(ts_cpp.language())
PARSER = Parser(CPP_LANGUAGE)


def _iter_nodes(root: Node) -> list[Node]:
    nodes: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        nodes.append(node)
        for child in reversed(node.children):
            stack.append(child)
    return nodes


def _node_text(source_bytes: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def _extract_method_name(field_node: Node, source_bytes: bytes) -> str:
    if field_node.type == "field_identifier":
        return _node_text(source_bytes, field_node)

    if field_node.type == "template_method":
        for child in field_node.children:
            if child.type == "field_identifier":
                return _node_text(source_bytes, child)

    return ""


def _is_supported_fdp_call(call_node: Node, source_bytes: bytes) -> bool:
    function_node = call_node.child_by_field_name("function")
    if function_node is None or function_node.type != "field_expression":
        return False

    receiver = function_node.child_by_field_name("argument")
    field = function_node.child_by_field_name("field")

    receiver_text = _node_text(source_bytes, receiver).strip()
    if receiver_text != "fdp":
        return False

    if field is None:
        return False

    method_name = _extract_method_name(field, source_bytes)
    return method_name in SUPPORTED


def _find_argument_list_ranges(source_bytes: bytes) -> list[tuple[int, int]]:
    tree = PARSER.parse(source_bytes)
    ranges: list[tuple[int, int]] = []

    for node in _iter_nodes(tree.root_node):
        if node.type != "call_expression":
            continue
        if not _is_supported_fdp_call(node, source_bytes):
            continue

        args = node.child_by_field_name("arguments")
        if args is None or args.type != "argument_list":
            continue

        # Replace the inner range between '(' and ')'.
        ranges.append((args.start_byte + 1, args.end_byte - 1))

    return ranges


def inject_ids(src: str, start_id: int, marker: str) -> tuple[str, int]:
    source_bytes = src.encode("utf-8")
    arg_ranges = _find_argument_list_ranges(source_bytes)
    if not arg_ranges:
        return src, 0

    next_id = start_id
    shift = 0
    changed = src

    for start, end in arg_ranges:
        start += shift
        end += shift
        args = changed[start:end]

        if marker in args:
            continue

        id_payload = f"/*{marker}:{next_id}*/ {next_id}"
        if args.strip():
            new_args = args + ", " + id_payload
        else:
            new_args = id_payload

        changed = changed[:start] + new_args + changed[end:]
        shift += len(new_args) - len(args)
        next_id += 1

    return changed, next_id - start_id

def main() -> None:
    parser = argparse.ArgumentParser(description="Inject stable FDP callsite IDs")
    parser.add_argument("--input", required=True, help="Input C/C++ source file")
    parser.add_argument("--output", required=True, help="Output C/C++ source file")
    parser.add_argument("--start-id", type=int, default=100000, help="Starting ID")
    parser.add_argument("--marker", default="FDP_ID", help="Marker comment prefix")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        src = f.read()

    try:
        transformed, count = inject_ids(src, args.start_id, args.marker)
    except Exception as exc:
        print(f"Failed to parse source with tree-sitter: {exc}", file=sys.stderr)
        sys.exit(2)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(transformed)

    print(f"Injected {count} FDP callsite IDs into {args.output}")


if __name__ == "__main__":
    main()
