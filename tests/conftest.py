
"""Configure isolated resources for the pytest suite."""

import os
import tempfile
from pathlib import Path


_TEST_DATABASE_DIRECTORY = Path(
    tempfile.mkdtemp(prefix="evidencefusion-pytest-")
)

_TEST_DATABASE_PATH = _TEST_DATABASE_DIRECTORY / "evidencefusion-test.db"

# pytest loads conftest.py before importing test modules.
# This must be set before tests import src.api.main.
os.environ["EVIDENCEFUSION_DB_PATH"] = str(_TEST_DATABASE_PATH)
