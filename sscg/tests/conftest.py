import os
import sys
import tempfile
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="sscg-tests-")
os.environ.update(SSCG_WORK_DIR=f"{_tmp}/work", SSCG_CONTEXT_DB=f"{_tmp}/context.db", SSCG_OKF_DIR=f"{_tmp}/okf")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402

from sscg import cache  # noqa: E402

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(cache, "OFFLINE", True)      # HTTP answers come from .cache or the test's own transport


def mkrepo(root: Path, files: dict) -> Path:
    for k, v in files.items():
        (root / k).parent.mkdir(parents=True, exist_ok=True)
        (root / k).write_text(v, encoding="utf-8")
    return root
