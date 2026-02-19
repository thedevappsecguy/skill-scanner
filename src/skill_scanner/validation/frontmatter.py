from __future__ import annotations

import re
from typing import Any

import yaml

FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n(.*)\Z", re.DOTALL)


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str] | None:
    match = FRONTMATTER_RE.match(text)
    if not match:
        return None
    raw_yaml, body = match.group(1), match.group(2)
    try:
        payload = yaml.safe_load(raw_yaml)
    except yaml.YAMLError:
        return None
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        return None
    return payload, body
