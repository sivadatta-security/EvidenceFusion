import json
from pathlib import Path

from jsonschema import Draft202012Validator


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCHEMA_PATH = PROJECT_ROOT / "data" / "schemas" / "event_schema.json"
EVENT_PATH = PROJECT_ROOT / "data" / "sample" / "sample_event.json"


def load_json(file_path):
    """Load a JSON file and return its contents."""
    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def validate_event():
    """Validate the sample event against the EvidenceFusion schema."""
    schema = load_json(SCHEMA_PATH)
    event = load_json(EVENT_PATH)

    Draft202012Validator.check_schema(schema)

    validator = Draft202012Validator(schema)
    validator.validate(event)

    print("VALIDATION PASSED")
    print("Event:", event["event_id"])
    print("Schema:", SCHEMA_PATH.name)
    print("Event file:", EVENT_PATH.name)


if __name__ == "__main__":
    validate_event()