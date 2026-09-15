"""Content-backed identities for future experiments; historical IDs stay intact."""
import hashlib


def record_uid(record):
    digest = hashlib.sha256(record["code"].encode("utf-8")).hexdigest()
    return hashlib.sha256(f"{record['sample_id']}|{digest}".encode()).hexdigest()


def prediction_index(rows):
    indexed = {}
    for row in rows:
        key = row.get("record_uid") or row["sample_id"]
        if key in indexed:
            raise ValueError("Duplicate prediction identity; use experiment_audit.py for a disclosed historical sensitivity analysis")
        indexed[key] = row
    return indexed
