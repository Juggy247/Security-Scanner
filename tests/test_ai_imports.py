from __future__ import annotations

import os
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def torch_loaded_after(statement: str) -> str:
    code = f"import sys; {statement}; print('torch' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=PROJECT_ROOT)
    assert out.returncode == 0, out.stderr[-300:]
    return out.stdout.strip()


def test_records_fetcher_and_text_processing_do_not_load_torch():
    assert torch_loaded_after("import ai.records, ai.fetcher, ai.text_processing") == "False"


def test_package_import_alone_does_not_load_torch():
    assert torch_loaded_after("import ai") == "False"


def test_scoring_is_the_module_that_loads_the_model_library():
    assert torch_loaded_after("import ai.scoring") == "True"
