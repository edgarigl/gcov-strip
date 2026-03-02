#!/usr/bin/env python3
import argparse
import re
import sys
from typing import Iterable, List, Set


SECTION_RE = re.compile(
    r"removing unused section '([^']+)'", re.IGNORECASE
)
CLONE_SUFFIXES = (
    "constprop",
    "isra",
    "part",
    "clone",
)
CLONE_RE = re.compile(
    rf"^(?P<base>.+?)\.(?:{'|'.join(CLONE_SUFFIXES)})(?:\.\d+)?$"
)


def extract_functions(
    lines: Iterable[str],
    normalize_clones: bool,
    echo_stderr: bool,
) -> List[str]:
    functions: List[str] = []
    seen: Set[str] = set()
    for line in lines:
        if echo_stderr:
            sys.stderr.write(line)
        match = SECTION_RE.search(line)
        if not match:
            continue
        section = match.group(1)
        text_index = section.rfind(".text.")
        if text_index == -1:
            continue
        name = section[text_index + len(".text.") :]
        if normalize_clones:
            clone_match = CLONE_RE.match(name)
            if clone_match:
                name = clone_match.group("base")
        if name not in seen:
            seen.add(name)
            functions.append(name)
    return functions


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract removed function names from ld --print-gc-sections output."
    )
    parser.add_argument(
        "-n",
        "--normalize-clones",
        action="store_true",
        help="Normalize GCC clone suffixes like .constprop/.isra/.part/.clone.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Do not echo input lines to stderr.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write function list to this file instead of stdout.",
    )
    args = parser.parse_args()

    functions = extract_functions(sys.stdin, args.normalize_clones, not args.quiet)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            for name in functions:
                handle.write(f"{name}\n")
    else:
        for name in functions:
            print(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
