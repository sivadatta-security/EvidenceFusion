"""Read-only access to the isolated external dataset demo database."""
import json
import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_DATABASE = PROJECT_ROOT / "data" / "external_dataset_demo.db"


class DatasetDatabaseUnavailable(FileNotFoundError):
    """Raised when the isolated demo database has not been created."""


def _connect_read_only(database_path: str | Path = DEFAULT_DATASET_DATABASE):
    path = Path(database_path).expanduser().resolve()
    if not path.is_file():
        raise DatasetDatabaseUnavailable(
            "External dataset sample is not available. Run the dataset importer first."
        )
    uri = path.as_uri() + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


def get_dataset_summary(database_path: str | Path = DEFAULT_DATASET_DATABASE) -> dict:
    """Return source and category counts without modifying any database."""
    connection = _connect_read_only(database_path)
    try:
        datasets = [
            {"dataset": dataset, "record_count": count}
            for dataset, count in connection.execute(
                "SELECT dataset, COUNT(*) FROM imported_records GROUP BY dataset ORDER BY dataset"
            ).fetchall()
        ]
        categories = [
            {"dataset": dataset, "event_type": event_type, "record_count": count}
            for dataset, event_type, count in connection.execute(
                """SELECT dataset, event_type, COUNT(*)
                   FROM imported_records
                   GROUP BY dataset, event_type
                   ORDER BY dataset, event_type"""
            ).fetchall()
        ]
        manifest = [
            {
                "dataset": dataset,
                "source_filename": filename,
                "selected_count": count,
                "sample_seed": seed,
                "imported_at": imported_at,
            }
            for dataset, filename, count, seed, imported_at in connection.execute(
                """SELECT dataset, source_filename, selected_count, sample_seed, imported_at
                   FROM import_manifest ORDER BY dataset"""
            ).fetchall()
        ]
        return {
            "database": "isolated external security datasets",
            "read_only": True,
            "total_records": sum(item["record_count"] for item in datasets),
            "datasets": datasets,
            "categories": categories,
            "manifest": manifest,
            "note": "Benchmark rows are kept separate from production investigation events; labels are not automatically treated as confirmed incidents.",
        }
    finally:
        connection.close()


def get_dataset_records(
    dataset: str | None = None,
    limit: int = 50,
    offset: int = 0,
    database_path: str | Path = DEFAULT_DATASET_DATABASE,
) -> dict:
    """Read a bounded page of dataset rows; never write or merge records."""
    if limit < 1 or limit > 100:
        raise ValueError("limit must be between 1 and 100")
    if offset < 0:
        raise ValueError("offset must be zero or greater")
    if dataset is not None:
        dataset = dataset.strip().upper()
        if not dataset:
            dataset = None

    connection = _connect_read_only(database_path)
    try:
        available_datasets = {
            row[0] for row in connection.execute(
                "SELECT dataset FROM import_manifest"
            ).fetchall()
        }
        if dataset is not None and dataset not in available_datasets:
            choices = ", ".join(sorted(available_datasets)) or "none imported"
            raise ValueError(f"dataset must be one of the imported datasets: {choices}")
        where = " WHERE dataset = ?" if dataset else ""
        params = (dataset, limit, offset) if dataset else (limit, offset)
        total = connection.execute(
            "SELECT COUNT(*) FROM imported_records" + where,
            (dataset,) if dataset else (),
        ).fetchone()[0]
        rows = connection.execute(
            """SELECT event_id, dataset, source, event_type, original_label,
                      label_semantics, source_row_number, timestamp, metadata_json
               FROM imported_records"""
            + where
            + " ORDER BY dataset, source_row_number LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        records = [
            {
                "event_id": row[0],
                "dataset": row[1],
                "source": row[2],
                "event_type": row[3],
                "original_label": row[4],
                "label_semantics": row[5],
                "source_row_number": row[6],
                "timestamp": row[7],
                "metadata": json.loads(row[8]),
            }
            for row in rows
        ]
        return {
            "read_only": True,
            "dataset": dataset,
            "total_records": total,
            "limit": limit,
            "offset": offset,
            "records": records,
        }
    finally:
        connection.close()
