from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
FIXTURES = SKILL_ROOT / "tests" / "fixtures"
sys.path.insert(0, str(SCRIPTS))

TestFunc = Callable[[], None]


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
