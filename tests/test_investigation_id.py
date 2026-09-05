"""Investigation identifiers must be reproducible across processes."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent


def _investigation_id_in_fresh_process(seed: str) -> str:
    """Run in a subprocess so PYTHONHASHSEED differs from this one."""
    code = (
        "import sys; sys.path.insert(0, r'%s');"
        "from app.main import run_pipeline;"
        "print(run_pipeline(%r, 'iam_access_key')['investigation_id'])" % (ROOT, seed)
    )
    output = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, cwd=ROOT
    )
    return output.stdout.strip().splitlines()[-1]


def test_investigation_id_is_stable_across_processes() -> None:
    seed = "AKIAIOSFODNN7EXAMPLE"
    first = _investigation_id_in_fresh_process(seed)
    second = _investigation_id_in_fresh_process(seed)
    assert first == second
    assert first.startswith("INV-2026-")


def test_different_seeds_produce_different_ids() -> None:
    assert _investigation_id_in_fresh_process("AKIAIOSFODNN7EXAMPLE") != _investigation_id_in_fresh_process(
        "AKIACOMPROMISEDKEY01"
    )
