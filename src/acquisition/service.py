
import hashlib
import shutil
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INCOMING_DIR = (PROJECT_ROOT / "data" / "incoming").resolve()
EVIDENCE_DIR = (PROJECT_ROOT / "data" / "evidence").resolve()


class AcquisitionError(Exception):
    """Raised when evidence acquisition cannot be completed."""


def sha256_file(file_path: Path) -> str:
    """Calculate SHA-256 using bounded memory."""
    digest = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def _ensure_inside_directory(path: Path, directory: Path) -> Path:
    """Resolve a path and reject paths outside an allowed directory."""
    resolved = path.resolve()
    allowed_directory = directory.resolve()

    try:
        resolved.relative_to(allowed_directory)
    except ValueError as error:
        raise AcquisitionError(
            "The requested path is outside the permitted directory."
        ) from error

    return resolved


def acquire_file(
    source_path: str | Path,
    acquired_by: str,
    artifact_type: str = "file",
    expected_sha256: str | None = None,
) -> dict:
    """
    Copy an incoming file into managed evidence storage.

    The source is not intentionally modified or deleted. The acquired copy
    is hashed and compared with the source and, optionally, an expected hash.
    """
    if not acquired_by or not acquired_by.strip():
        raise AcquisitionError("acquired_by must not be empty.")

    if not artifact_type or not artifact_type.strip():
        raise AcquisitionError("artifact_type must not be empty.")

    INCOMING_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    source = _ensure_inside_directory(Path(source_path), INCOMING_DIR)

    if not source.is_file():
        raise AcquisitionError(
            "The source must be an existing file inside data/incoming."
        )

    if expected_sha256 is not None:
        expected_sha256 = expected_sha256.strip().lower()

        if (
            len(expected_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_sha256)
        ):
            raise AcquisitionError(
                "expected_sha256 must contain 64 hexadecimal characters."
            )

    evidence_id = f"EVD-{uuid4().hex[:12].upper()}"
    destination = EVIDENCE_DIR / f"{evidence_id}_{source.name}"

    source_hash_before = sha256_file(source)

    try:
        shutil.copy2(source, destination)

        copied_hash = sha256_file(destination)
        source_hash_after = sha256_file(source)

        if source_hash_before != source_hash_after:
            raise AcquisitionError(
                "The source changed during acquisition; verification failed."
            )

        if copied_hash != source_hash_before:
            raise AcquisitionError(
                "The acquired copy does not match the source hash."
            )

        if expected_sha256 is None:
            verification_status = "not_verified"
        elif copied_hash == expected_sha256:
            verification_status = "verified"
        else:
            verification_status = "failed"

        # Use stable project-relative references instead of asking Windows
        # to calculate relative paths across potentially different path forms.
        evidence_reference = (
            Path("data") / "evidence" / destination.name
        ).as_posix()

        source_reference = (
            Path("data") / "incoming" / source.name
        ).as_posix()

        return {
            "evidence_id": evidence_id,
            "artifact_type": artifact_type.strip(),
            "source_reference": evidence_reference,
            "original_filename": source.name,
            "sha256": copied_hash,
            "hash_algorithm": "SHA-256",
            "acquisition_method": "local_file_copy",
            "acquired_at": datetime.now(timezone.utc).isoformat(),
            "acquired_by": acquired_by.strip(),
            "verification_status": verification_status,
            "metadata": {
                "source_reference": source_reference,
                "source_sha256_before": source_hash_before,
                "source_sha256_after": source_hash_after,
                "copy_sha256": copied_hash,
                "expected_sha256_provided": expected_sha256 is not None,
            },
        }

    except Exception:
        # Clean up a partial copy without deleting or changing the source.
        if destination.exists():
            destination.unlink()
        raise


def remove_acquired_file(evidence: dict) -> None:
    """
    Remove a managed copy when its database registration fails.

    Only files inside the managed evidence directory are eligible.
    The original incoming source is never deleted.
    """
    reference = evidence.get("source_reference")

    if not reference:
        return

    candidate = (PROJECT_ROOT / reference).resolve()
    managed_directory = EVIDENCE_DIR.resolve()

    try:
        candidate.relative_to(managed_directory)
    except ValueError:
        raise AcquisitionError(
            "Refusing to remove a file outside managed evidence storage."
        )

    if candidate.is_file():
        candidate.unlink()

def verify_evidence_integrity(evidence: dict) -> dict:
    """
    Recalculate the SHA-256 hash of a managed evidence copy
    and compare it with the hash stored during acquisition.
    """
    expected_hash = evidence.get("sha256")
    reference = evidence.get("source_reference")

    result = {
        "evidence_id": evidence.get("evidence_id"),
        "expected_sha256": expected_hash,
        "calculated_sha256": None,
        "verification_status": "unavailable",
        "reason": None,
    }

    if not reference:
        result["reason"] = "Evidence file reference is missing."
        return result

    candidate = (PROJECT_ROOT / reference).resolve()

    try:
        candidate.relative_to(EVIDENCE_DIR.resolve())
    except ValueError:
        result["verification_status"] = "failed"
        result["reason"] = "Evidence path is outside managed storage."
        return result

    if not candidate.is_file():
        result["reason"] = "Evidence file is missing."
        return result

    if (
        evidence.get("hash_algorithm") != "SHA-256"
        or not expected_hash
        or len(expected_hash) != 64
        or any(c not in "0123456789abcdefABCDEF" for c in expected_hash)
    ):
        result["reason"] = "A valid stored SHA-256 baseline is unavailable."
        return result

    try:
        calculated_hash = sha256_file(candidate)
    except OSError:
        result["reason"] = "Evidence file could not be read."
        return result

    result["calculated_sha256"] = calculated_hash

    if calculated_hash.lower() == expected_hash.lower():
        result["verification_status"] = "verified"
        result["reason"] = "Current hash matches the stored acquisition hash."
    else:
        result["verification_status"] = "failed"
        result["reason"] = "Current hash differs from the stored acquisition hash."

    return result