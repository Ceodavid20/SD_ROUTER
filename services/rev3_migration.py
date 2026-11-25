"""Private, read-only JSON snapshots and an inactive MySQL staging import.

No Flask backend selection, router clients, credential resolution or source repair.
Every legacy byte (including replay ledgers) survives; no settings are activated.
"""
from contextlib import contextmanager
from datetime import UTC, datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
from uuid import uuid4

from services.deployment_service import profile_path
from services.json_storage import StorageService, StorageError
from services.rev3_readiness import load_register, DEFAULT_REGISTER


SCHEMA = Path(__file__).resolve().parents[1] / "database/mysql/001_rev3_schema.sql"
CHUNK_BYTES = 131072
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024
SEGMENT = re.compile(r"data/traffic_segments/traffic-\d{4}-\d{2}-\d{2}-\d{4}\.jsonl\Z")
DOCUMENTS = {("output/" if name == "router_config.json" else "data/") + name
             for name in StorageService.DEFAULTS}
ARTIFACTS = {"mysql-schema.sql", "mysql-import.sql"}


class MigrationError(ValueError):
    """Safe errors never include input values, SQL or database credentials."""


def _json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise MigrationError("Duplicate JSON fields in migration input.")
            result[key] = value
        return result
    def invalid(_):
        raise MigrationError("Non-finite migration values are not allowed.")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise MigrationError("Invalid migration JSON; private contents withheld.") from exc


def _no_secrets(value):
    """Reject known credential containers rather than copying them into the DB.

    References and hash-only enrollment grants are permitted; private keys and
    plaintext login fields are not. Do not print the offending key or its value.
    """
    if isinstance(value, dict):
        for key, child in value.items():
            name = key.lower()
            if (any(word in name for word in ("password", "private_key", "community"))
                    or ("secret" in name and not name.endswith(("_ref", "_configured")))
                    or name in {"username", "api_username", "api_login", "token", "enrollment_token"}):
                raise MigrationError("Credential-bearing legacy data requires private review before migration.")
            _no_secrets(child)
    elif isinstance(value, list):
        for child in value:
            _no_secrets(child)


def _read(path, maximum=MAX_FILE_BYTES):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise MigrationError("Migration files must be bounded regular files.")
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise MigrationError("Migration file exceeds its size limit.")
    return raw


def _write(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _destination(config, destination):
    path = profile_path(config, destination)
    for protected in (config["DATA_DIR"], config["OUTPUT_DIR"]):
        active = profile_path(config, protected)
        if path == active or path.is_relative_to(active) or active.is_relative_to(path):
            raise MigrationError("Use a new private directory separate from active storage.")
    if path.exists() or not path.parent.is_dir() or path.parent.stat().st_mode & 0o077:
        raise MigrationError("Use a new directory inside an existing owner-only parent.")
    return path


def _entry(name, raw):
    return {"name": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _summary(documents):
    return {"documents": len(documents), "routers": len(documents["routers.json"]),
            "paths": len(documents["routing_paths.json"]["paths"]),
            "replay_records": sum(len(documents[name]["seen_requests"]) for name in (
                "router_communication.json", "router_communication_v2.json",
                "router_traffic_v2.json", "optimization_communication.json"))}


@contextmanager
def _source(config):
    if config.get("SIMULATION_MODE") is not True or config.get("LIVE_ROUTING_ENABLED") is not False:
        raise MigrationError("Preserve simulation and disabled routing execution before preparing a migration.")
    data = profile_path(config, config["DATA_DIR"])
    output = profile_path(config, config["OUTPUT_DIR"])
    if data == output or data.is_relative_to(output) or output.is_relative_to(data):
        raise MigrationError("Source data and output directories must be separate.")
    lock = data / ".storage.lock"
    if os.name == "nt" or lock.is_symlink() or not lock.is_file():
        raise MigrationError("An initialized profile with a consistent read-only lock is required.")
    import fcntl
    # Do not initialize storage or run its normal lock/recovery path.
    with lock.open("rb") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
        yield StorageService(data, output)


def _validate_documents(storage, root):
    result = {}
    for name in sorted(StorageService.DEFAULTS):
        relative = ("output/" if name == "router_config.json" else "data/") + name
        value = _json(_read(root / relative))
        storage._validate(name, value)
        _no_secrets(value)
        result[name] = value
    if result["router_enrollment.json"]["pending"] is not None or result["router_traffic_v2.json"]["pending_reading"] is not None:
        raise MigrationError("A legacy transaction is pending; let normal storage recovery finish before retrying.")
    return result


def _validate_segment(raw, storage):
    count = 0
    for line in raw.splitlines(keepends=True):
        if not line.endswith(b"\n") or len(line) > 65536:
            raise MigrationError("Incomplete or oversized traffic history record; no source repair attempted.")
        value = _json(line)
        storage._validate_traffic(value)
        _no_secrets(value)
        count += 1
    return count


def _sql_parts(root, manifest):
    identity = manifest["snapshot_id"]
    timestamp = manifest["captured_at"].replace("T", " ").removesuffix("Z")
    yield b"-- Private inactive staging import. Never use --force.\nSET NAMES utf8mb4;\nSET SESSION sql_mode='STRICT_ALL_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';\nSET time_zone='+00:00';\nSTART TRANSACTION;\n"
    yield ("INSERT INTO sdr_migration_batches (snapshot_id,captured_at,expected_files,traffic_records,state) "
           f"VALUES ('{identity}','{timestamp}',{len(manifest['files'])},{manifest['counts']['traffic_records']},'staged');\n").encode()
    for row in manifest["files"]:
        name = row["name"]
        chunks = math.ceil(row["bytes"] / CHUNK_BYTES)
        yield ("INSERT INTO sdr_migration_files (snapshot_id,file_name,byte_count,sha256,expected_chunks) "
               f"VALUES ('{identity}','{name}',{row['bytes']},'{row['sha256']}',{chunks});\n").encode()
        with (root / name).open("rb") as stream:
            for number in range(chunks):
                raw = stream.read(CHUNK_BYTES)
                digest = hashlib.sha256(raw).hexdigest()
                yield ("INSERT INTO sdr_migration_chunks (snapshot_id,file_name,chunk_number,byte_count,sha256,payload) "
                       f"VALUES ('{identity}','{name}',{number},{len(raw)},'{digest}',X'{raw.hex()}');\n").encode()
    yield b"COMMIT;\n"


def prepare(config, destination, *, register_path=DEFAULT_REGISTER):
    register = load_register(register_path)
    decision = next(d for d in register["decisions"] if d["id"] == "database_engine")
    if decision["status"] != "confirmed" or decision["selection"] != "mysql":
        raise MigrationError("Confirm MySQL in the planning register before preparing its migration.")
    destination = _destination(config, destination)
    created = False
    try:
        with _source(config) as storage:
            documents = {name: storage._read_unlocked(name) for name in StorageService.DEFAULTS}
            if documents["router_enrollment.json"]["pending"] is not None or documents["router_traffic_v2.json"]["pending_reading"] is not None:
                raise MigrationError("A legacy transaction is pending; let normal recovery finish before retrying.")
            for value in documents.values():
                _no_secrets(value)
            names = sorted(DOCUMENTS | {"data/" + item["file"] for item in documents["traffic_history.json"]["segments"]})
            referenced = {item["file"] for item in documents["traffic_history.json"]["segments"]}
            segments = storage.data_dir / "traffic_segments"
            if segments.is_symlink() or not segments.is_dir():
                raise MigrationError("Traffic history directory is unavailable.")
            if any("traffic_segments/" + p.name not in referenced for p in segments.iterdir()):
                raise MigrationError("Unreferenced traffic files require review; no data was discarded.")
            total = 0
            for name in names:
                source = (storage.output_dir if name.startswith("output/") else storage.data_dir) / name.split("/", 1)[1]
                if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_FILE_BYTES:
                    raise MigrationError("Invalid or oversized snapshot source.")
                total += source.stat().st_size
            if total > MAX_SNAPSHOT_BYTES:
                raise MigrationError("Snapshot exceeds the bounded preparation limit; use a reviewed offline migration.")
            destination.mkdir(mode=0o700)
            created = True
            manifest = {"schema_version": 1, "snapshot_id": uuid4().hex,
                "captured_at": datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                "target": "mysql", "runtime_cutover_authorized": False, "router_execution_authorized": False,
                "files": [], "artifacts": [], "counts": {**_summary(documents), "segments": len(referenced), "traffic_records": 0}}
            for name in names:
                source = (storage.output_dir if name.startswith("output/") else storage.data_dir) / name.split("/", 1)[1]
                raw = _read(source)
                if SEGMENT.fullmatch(name):
                    manifest["counts"]["traffic_records"] += _validate_segment(raw, storage)
                _write(destination / name, raw)
                manifest["files"].append(_entry(name, raw))
        # The source lock is released before SQL encoding or database access.
        schema = _read(SCHEMA)
        _write(destination / "mysql-schema.sql", schema)
        manifest["artifacts"].append(_entry("mysql-schema.sql", schema))
        sql = destination / "mysql-import.sql"
        digest, length = hashlib.sha256(), 0
        with sql.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            for part in _sql_parts(destination, manifest):
                stream.write(part); digest.update(part); length += len(part)
            stream.flush(); os.fsync(stream.fileno())
        manifest["artifacts"].append({"name": sql.name, "bytes": length, "sha256": digest.hexdigest()})
        _write(destination / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
        return verify(destination)
    except (OSError, StorageError, ValueError, KeyError, TypeError) as exc:
        if created:
            shutil.rmtree(destination)
        if isinstance(exc, MigrationError):
            raise
        raise MigrationError("Migration preparation failed; source data was not modified; private details withheld.") from exc


def _file_hash(path):
    digest, length = hashlib.sha256(), 0
    if path.is_symlink() or not path.is_file():
        raise MigrationError("Bundle artifacts must be regular files.")
    with path.open("rb") as stream:
        for raw in iter(lambda: stream.read(CHUNK_BYTES), b""):
            digest.update(raw); length += len(raw)
    return length, digest.hexdigest()


def verify(bundle):
    try:
        root = Path(bundle).expanduser().absolute()
        if any(p.is_symlink() for p in (root, *root.parents)) or not root.is_dir() or root.stat().st_mode & 0o077:
            raise MigrationError("Use an owner-only bundle without symbolic links.")
        manifest = _json(_read(root / "manifest.json", MAX_MANIFEST_BYTES))
        expected = {"schema_version", "snapshot_id", "captured_at", "target", "runtime_cutover_authorized",
                    "router_execution_authorized", "files", "artifacts", "counts"}
        if (not isinstance(manifest, dict) or set(manifest) != expected
                or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1
                or manifest["target"] != "mysql" or manifest["runtime_cutover_authorized"] is not False
                or manifest["router_execution_authorized"] is not False
                or not isinstance(manifest["snapshot_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", manifest["snapshot_id"])):
            raise MigrationError("Invalid inactive migration manifest.")
        timestamp = datetime.strptime(manifest["captured_at"], "%Y-%m-%dT%H:%M:%S.%fZ")
        if timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != manifest["captured_at"]:
            raise MigrationError("Invalid snapshot timestamp.")
        counts = manifest["counts"]
        if (not isinstance(counts, dict) or set(counts) != {"documents", "routers", "paths", "replay_records", "segments", "traffic_records"}
                or any(type(v) is not int or v < 0 for v in counts.values())):
            raise MigrationError("Invalid migration counts.")
        seen, total = set(), 0
        for group in ("files", "artifacts"):
            if not isinstance(manifest[group], list) or len(manifest[group]) > 5000:
                raise MigrationError("Invalid migration file inventory.")
            for row in manifest[group]:
                if (not isinstance(row, dict) or set(row) != {"name", "bytes", "sha256"}
                        or not isinstance(row["name"], str) or row["name"] in seen
                        or type(row["bytes"]) is not int or row["bytes"] < 0
                        or not isinstance(row["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", row["sha256"])):
                    raise MigrationError("Invalid migration file metadata.")
                name = row["name"]
                if (group == "files" and name not in DOCUMENTS and not SEGMENT.fullmatch(name)) or (group == "artifacts" and name not in ARTIFACTS):
                    raise MigrationError("Unexpected or unsafe migration file path.")
                seen.add(name)
                path = root / name
                if any(p.is_symlink() for p in path.parents) or path.stat().st_mode & 0o077:
                    raise MigrationError("Bundle files must stay private without symbolic links.")
                maximum = MAX_FILE_BYTES if group == "files" else 2 * MAX_SNAPSHOT_BYTES + 8 * 1024 * 1024
                if row["bytes"] > maximum or path.stat().st_size != row["bytes"]:
                    raise MigrationError("Invalid bundle artifact size.")
                if path.stat().st_size != row["bytes"] or row["bytes"] > 2 * MAX_SNAPSHOT_BYTES + 8 * 1024 * 1024:
                    raise MigrationError("Invalid bundle artifact size.")
                if _file_hash(path) != (row["bytes"], row["sha256"]):
                    raise MigrationError("Migration checksum mismatch; no import is permitted.")
                if group == "files":
                    total += row["bytes"]
                    if row["bytes"] > MAX_FILE_BYTES or total > MAX_SNAPSHOT_BYTES:
                        raise MigrationError("Migration snapshot exceeds size limits.")
        storage = StorageService(root / "data", root / "output")
        documents = _validate_documents(storage, root)
        expected_names = DOCUMENTS | {"data/" + item["file"] for item in documents["traffic_history.json"]["segments"]}
        if {r["name"] for r in manifest["files"]} != expected_names or {r["name"] for r in manifest["artifacts"]} != ARTIFACTS:
            raise MigrationError("Migration inventory is incomplete.")
        actual = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}
        if actual != seen | {"manifest.json"} or any(p.is_symlink() for p in root.rglob("*")):
            raise MigrationError("Unexpected files or links in the migration bundle.")
        records = sum(_validate_segment(_read(root / name), storage) for name in expected_names if SEGMENT.fullmatch(name))
        if counts != {**_summary(documents), "segments": len(expected_names - DOCUMENTS), "traffic_records": records}:
            raise MigrationError("Migration record counts do not reconcile.")
        if _file_hash(root / "mysql-schema.sql") != _file_hash(SCHEMA):
            raise MigrationError("The bundle uses an unexpected schema revision.")
        digest = hashlib.sha256()
        for part in _sql_parts(root, manifest):
            digest.update(part)
        if digest.hexdigest() != _file_hash(root / "mysql-import.sql")[1]:
            raise MigrationError("SQL artifact differs from the verified snapshot.")
        return manifest
    except (OSError, StorageError, ValueError, KeyError, TypeError, AttributeError) as exc:
        if isinstance(exc, MigrationError):
            raise
        raise MigrationError("Cannot verify migration bundle; private details withheld.") from exc


def rehearse_restore(config, bundle, destination):
    manifest = verify(bundle)
    destination = _destination(config, destination)
    root = Path(bundle).absolute()
    if destination == root or destination.is_relative_to(root) or root.is_relative_to(destination):
        raise MigrationError("Restore into a separate new directory, outside the verified bundle.")
    created = False
    try:
        destination.mkdir(mode=0o700)
        created = True
        for row in manifest["files"]:
            _write(destination / row["name"], _read(root / row["name"]))
        (destination / "data/traffic_segments").mkdir(mode=0o700, exist_ok=True)
        _write(destination / "data/.storage.lock", b"")
        _validate_documents(StorageService(destination / "data", destination / "output"), destination)
        return {"restored": True, "runtime_cutover_authorized": False, "counts": manifest["counts"]}
    except (OSError, StorageError, ValueError) as exc:
        if created:
            shutil.rmtree(destination)
        raise MigrationError("Restore rehearsal failed; active storage was not touched.") from exc
