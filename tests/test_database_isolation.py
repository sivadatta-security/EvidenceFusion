from pathlib import Path

from src.api import database


def test_pytest_database_is_separate_from_project_database():
    project_database = (
        database.PROJECT_ROOT / "data" / "evidencefusion.db"
    ).resolve()

    assert database.DATABASE_PATH.resolve() != project_database
    assert database.DATABASE_PATH.name == "evidencefusion-test.db"
