import json
from pathlib import Path

from jsonschema import Draft202012Validator


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCHEMA_PATH = PROJECT_ROOT / "data" / "schemas" / "event_schema.json"


def load_json(file_path):
    """Load JSON data from a file."""
    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def ingest_event(file_path):
    """
    Load and validate a normalized event.

    Returns:
        dict: Validated event data.
    """
    schema = load_json(SCHEMA_PATH)
    event = load_json(Path(file_path))

    Draft202012Validator.check_schema(schema)

    validator = Draft202012Validator(schema)
    validator.validate(event)

    return event


if __name__ == "__main__":
    sample_event = PROJECT_ROOT / "data" / "sample" / "sample_event.json"

    event = ingest_event(sample_event)

    print("INGESTION SUCCESSFUL")
    print("Event ID:", event["event_id"])
    print("Event Type:", event["event_type"])
    print("Source:", event["source"])