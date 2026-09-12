import tempfile
import unittest
from pathlib import Path

from src.api import database


class TestDatabase(unittest.TestCase):

    def setUp(self):
        """Create a temporary database for each test."""
        self.temp_directory = tempfile.TemporaryDirectory()

        self.original_data_dir = database.DATA_DIR
        self.original_database_path = database.DATABASE_PATH

        database.DATA_DIR = Path(self.temp_directory.name)
        database.DATABASE_PATH = (
            database.DATA_DIR / "test_evidencefusion.db"
        )

        database.initialize_database()

    def tearDown(self):
        """Restore database paths and remove the temporary database."""
        database.DATA_DIR = self.original_data_dir
        database.DATABASE_PATH = self.original_database_path

        self.temp_directory.cleanup()

    def test_empty_database(self):
        """Verify that a new database initially contains no events."""
        events = database.get_events()

        self.assertEqual(events, [])

    def test_insert_and_retrieve_event(self):
        """Verify that an event can be inserted and retrieved."""
        event = {
            "event_id": "TEST001",
            "timestamp": "2026-09-01T10:30:00Z",
            "source": "email",
            "event_type": "email_received",
            "user": "test_user",
            "host": "TEST-PC",
            "source_ip": None,
            "destination_ip": None,
            "domain": "example.test",
            "artifact": "suspicious_url",
            "hash": None,
            "description": "Test suspicious email",
            "confidence": 0.90
        }

        database.insert_event(event)

        events = database.get_events()

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], "TEST001")
        self.assertEqual(events[0][2], "email")
        self.assertEqual(events[0][3], "email_received")
        self.assertEqual(events[0][4], "test_user")
        self.assertEqual(events[0][5], "TEST-PC")
        self.assertEqual(events[0][8], "example.test")
        self.assertEqual(events[0][12], 0.90)


if __name__ == "__main__":
    unittest.main()