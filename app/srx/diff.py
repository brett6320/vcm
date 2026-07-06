"""Line-aligned side-by-side diff of two config texts, for the pre-apply
approval screen. Pure/stdlib so it's trivially testable."""
from __future__ import annotations

import difflib


def side_by_side(before: str, after: str) -> list[dict]:
    """Return aligned rows [{left, right, kind}] where kind is one of
    equal | replace | delete | insert."""
    a = (before or "").splitlines()
    b = (after or "").splitlines()
    rows: list[dict] = []
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                rows.append({"left": a[i1 + k], "right": b[j1 + k], "kind": "equal"})
        elif tag == "replace":
            la, rb = a[i1:i2], b[j1:j2]
            for k in range(max(len(la), len(rb))):
                rows.append({"left": la[k] if k < len(la) else "",
                             "right": rb[k] if k < len(rb) else "",
                             "kind": "replace"})
        elif tag == "delete":
            for k in range(i1, i2):
                rows.append({"left": a[k], "right": "", "kind": "delete"})
        elif tag == "insert":
            for k in range(j1, j2):
                rows.append({"left": "", "right": b[k], "kind": "insert"})
    return rows


def changed(before: str, after: str) -> bool:
    return (before or "").strip() != (after or "").strip()
