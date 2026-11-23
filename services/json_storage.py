"""Validated JSON storage with atomic replacement and locked traffic appends.

All writers must use this service. Advisory locks coordinate controller
processes on one machine; these files are not a network-filesystem protocol.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime
import json
import math
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Any
from uuid import uuid4


class StorageError(Exception):
    """Stored data could not be read or safely written."""


class ValidationError(StorageError, ValueError):
    """A document or record violates the storage contract."""


_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()
_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_MAX_SEGMENT_BYTES = 8 * 1024 * 1024
_SEGMENT = re.compile(r"traffic_segments/traffic-\d{4}-\d{2}-\d{2}-\d{4}\.jsonl\Z")


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValidationError("A timezone-aware ISO 8601 timestamp is required.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("Invalid timestamp.") from exc
    if parsed.tzinfo is None:
        raise ValidationError("Timestamps must include a timezone.")
    return parsed.astimezone(UTC)


def _text(value: Any, label: str, maximum: int = 500) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValidationError(f"{label} must be a nonempty string of at most {maximum} characters.")


def _encode(value: Any) -> bytes:
    def validate_keys(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValidationError("JSON object property names must be strings.")
                validate_keys(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                validate_keys(child)

    try:
        validate_keys(value)
        return (json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValidationError("Data must contain finite JSON values.") from exc


class StorageService:
    """Own the controller's internal documents and separate output document."""

    DEFAULTS = {
        "routers.json": [],
        "routing_paths.json": {},
        "router_communication.json": {
            "schema_version": 1, "routers": {}, "seen_requests": [], "rate_limits": {},
        },
        "router_communication_v2.json": {
            "schema_version": 2, "routers": {}, "seen_requests": [], "issued_responses": [],
        },
        "router_traffic_v2.json": {
            "schema_version": 1, "routers": {}, "seen_requests": [],
            "rate_limits": {}, "pending_reading": None,
        },
        "traffic_history.json": {"schema_version": 1, "storage": "segmented_jsonl", "segments": []},
        "averages.json": [],
        "optimization_results.json": [],
        "routing_costs.json": [],
        "automation_settings.json": {
            "schema_version": 1,
            "mode": "simulation",
            "automation": "off",
            "routing_changes_enabled": False,
            "monitoring_interval_seconds": 60,
            "averaging_window": 5,
            "start_time": None,
            "stop_time": None,
        },
        "activity_logs.json": [],
        "router_config.json": {"schema_version": 1, "commands": []},
    }

    def __init__(self, data_dir: str | Path, output_dir: str | Path) -> None:
        self.data_dir = Path(data_dir).absolute()
        self.output_dir = Path(output_dir).absolute()

    def _prepare_directories(self) -> None:
        for directory in (self.data_dir, self.output_dir, self.data_dir / "traffic_segments"):
            if directory.is_symlink():
                raise StorageError("Storage directories must not be symbolic links.")
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _path(self, name: str) -> Path:
        if name not in self.DEFAULTS:
            raise ValidationError("Unknown storage document.")
        root = self.output_dir if name == "router_config.json" else self.data_dir
        path = root / name
        if path.is_symlink():
            raise StorageError("Storage files must not be symbolic links.")
        return path

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Lock one transaction across threads and processes, including readers."""
        try:
            self._prepare_directories()
            lock_path = self.data_dir / ".storage.lock"
            with _LOCKS_GUARD:
                lock = _LOCKS.setdefault(str(lock_path.resolve()), threading.RLock())
            with lock:
                flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                if lock_path.is_symlink():
                    raise StorageError("Lock file must not be a symbolic link.")
                descriptor = os.open(lock_path, flags, 0o600)
                with os.fdopen(descriptor, "r+b") as stream:
                    if os.name == "nt":
                        import msvcrt

                        if stream.seek(0, os.SEEK_END) == 0:
                            stream.write(b"\0")
                            stream.flush()
                        stream.seek(0)
                        msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
                    try:
                        yield
                    finally:
                        if os.name == "nt":
                            stream.seek(0)
                            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                        else:
                            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        except OSError as exc:
            raise StorageError("Storage I/O operation failed.") from exc

    def initialize(self) -> None:
        """Create missing files, validate existing ones, and seed one event."""
        with self._locked():
            for name, default in self.DEFAULTS.items():
                path = self._path(name)
                if not path.exists():
                    initial = self._initial_document(name, default)
                    self._write_unlocked(name, initial, backup=False)
                else:
                    self._read_unlocked(name)
            self._flush_pending_traffic_unlocked(self._read_unlocked("router_traffic_v2.json"))
            events = self._read_unlocked("activity_logs.json")
            changed = False
            cleaned_events = []
            startup_found = False
            for event in events:
                if event["message"] == "Controller changed to live read-only company operations.":
                    event["message"] = "Routing changes disabled."
                    changed = True
                if event["message"] == "Controller JSON storage initialized.":
                    event["message"] = "System started."
                    changed = True
                if event["message"] == "System started.":
                    if startup_found:
                        changed = True
                        continue
                    startup_found = True
                cleaned_events.append(event)
            events = cleaned_events
            if not startup_found:
                events.append(self._event("system", "System started."))
                changed = True
            if changed:
                self._write_unlocked("activity_logs.json", events)

    @staticmethod
    def _initial_document(name: str, default: Any) -> Any:
        if name == "routing_paths.json":
            from services.path_config_service import DEFAULT_ROUTING_PATHS

            return deepcopy(DEFAULT_ROUTING_PATHS)
        return deepcopy(default)

    def read_json(self, name: str) -> Any:
        with self._locked():
            return self._read_unlocked(name)

    def _read_unlocked(self, name: str) -> Any:
        path = self._path(name)
        try:
            if path.stat().st_size > _MAX_DOCUMENT_BYTES:
                raise StorageError("Storage document exceeds the safety size limit.")
            value = json.loads(
                path.read_text(encoding="utf-8"),
                parse_constant=self._invalid_constant,
                object_pairs_hook=self._unique_object,
            )
        except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise StorageError(f"Cannot read valid JSON from {name}; the backup is preserved.") from exc
        self._validate(name, value)
        return value

    @staticmethod
    def _invalid_constant(value: str) -> None:
        raise ValidationError("Non-finite JSON numbers are not permitted.")

    @staticmethod
    def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValidationError("Duplicate JSON object properties are not permitted.")
            result[key] = value
        return result

    def write_json(self, name: str, value: Any) -> None:
        with self._locked():
            self._write_unlocked(name, value)

    def update_json(self, name: str, updater: Callable[[Any], Any]) -> Any:
        """Read, change, validate, back up, and replace under the same lock."""
        with self._locked():
            result = updater(self._read_unlocked(name))
            self._write_unlocked(name, result)
            return result

    @staticmethod
    def _atomic_bytes(path: Path, content: bytes) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            StorageService._sync_directory(path.parent)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @staticmethod
    def _sync_directory(path: Path) -> None:
        if os.name != "nt":
            directory = os.open(path, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)

    def _write_unlocked(self, name: str, value: Any, *, backup: bool = True) -> None:
        self._validate(name, value)
        encoded = _encode(value)
        if len(encoded) > _MAX_DOCUMENT_BYTES:
            raise ValidationError("Storage document exceeds the safety size limit.")
        path = self._path(name)
        if backup and path.exists():
            # Validate first: never replace the last good backup with corrupt input.
            self._read_unlocked(name)
            self._atomic_bytes(path.with_suffix(path.suffix + ".bak"), path.read_bytes())
        self._atomic_bytes(path, encoded)

    @staticmethod
    def _event(category: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        event = {"event_id": str(uuid4()), "timestamp": _utc_timestamp(), "category": category, "message": message}
        if details is not None:
            event["details"] = details
        return event

    def append_activity(self, category: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        event = self._event(category, message, details)
        self.update_json("activity_logs.json", lambda events: [*events, event])
        return event

    def list_activity(self, limit: int = 50) -> list[dict[str, Any]]:
        self._limit(limit)
        return list(reversed(self.read_json("activity_logs.json")[-limit:]))

    @staticmethod
    def _limit(limit: int) -> None:
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValidationError("Limit must be an integer between 1 and 10000.")

    def _segment_path(self, relative: str) -> Path:
        if not isinstance(relative, str) or not _SEGMENT.fullmatch(relative):
            raise ValidationError("Invalid traffic segment path.")
        path = self.data_dir / relative
        if path.is_symlink() or path.parent.is_symlink():
            raise StorageError("Traffic segments must not be symbolic links.")
        return path

    def append_traffic(self, reading: dict[str, Any]) -> dict[str, Any]:
        """Append a complete JSON line; rewrite the small manifest only on rotation."""
        self._validate_traffic(reading)
        encoded = self._traffic_bytes(reading)
        if len(encoded) > 65536:
            raise ValidationError("Traffic reading is too large.")
        with self._locked():
            self._flush_pending_traffic_unlocked(self._read_unlocked("router_traffic_v2.json"))
            relative, _ = self._traffic_target_unlocked(reading, len(encoded))
            with self._segment_path(relative).open("ab") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        return deepcopy(reading)

    @staticmethod
    def _traffic_bytes(reading: dict[str, Any]) -> bytes:
        return (json.dumps(reading, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")

    def _traffic_target_unlocked(self, reading: dict[str, Any], size: int) -> tuple[str, int]:
        date = _timestamp(reading["timestamp"]).date().isoformat()
        manifest = self._read_unlocked("traffic_history.json")
        entries = [entry for entry in manifest["segments"] if entry["date"] == date]
        relative = entries[-1]["file"] if entries else None
        segment = self._segment_path(relative) if relative else None
        if segment is None or segment.stat().st_size + size > _MAX_SEGMENT_BYTES:
            relative = f"traffic_segments/traffic-{date}-{len(entries) + 1:04d}.jsonl"
            segment = self._segment_path(relative)
            # An unreferenced file from an interrupted rotation must be empty.
            if segment.exists() and segment.stat().st_size:
                raise StorageError("Unreferenced traffic segment requires repair.")
            segment.touch(mode=0o600, exist_ok=True)
            self._sync_directory(segment.parent)
            manifest["segments"].append({"date": date, "file": relative})
            self._write_unlocked("traffic_history.json", manifest)
        with segment.open("rb") as stream:
            offset = stream.seek(0, os.SEEK_END)
            if offset:
                stream.seek(-1, os.SEEK_END)
                if stream.read(1) != b"\n":
                    raise StorageError("Traffic segment has an incomplete final record; repair it before appending.")
        return relative, offset

    def _flush_pending_traffic_unlocked(self, state: dict[str, Any]) -> None:
        """Complete one committed append exactly once, including after a crash.

        The persisted file/offset and expected bytes distinguish an unwritten,
        partially written or fully written line. Unrelated bytes fail closed.
        All history writers hold the same lock and flush this outbox first.
        """
        pending = state["pending_reading"]
        if pending is None:
            return
        manifest = self._read_unlocked("traffic_history.json")
        if not any(entry["file"] == pending["file"] for entry in manifest["segments"]):
            raise StorageError("Pending traffic segment is absent from history.")
        encoded = self._traffic_bytes(pending["reading"])
        with self._segment_path(pending["file"]).open("r+b") as stream:
            size = stream.seek(0, os.SEEK_END)
            offset = pending["offset"]
            if not offset <= size <= offset + len(encoded):
                raise StorageError("Pending traffic offset conflicts with history.")
            if offset:
                stream.seek(offset - 1)
                if stream.read(1) != b"\n":
                    raise StorageError("Pending traffic offset is not a record boundary.")
            stream.seek(offset)
            existing = stream.read()
            if not encoded.startswith(existing):
                raise StorageError("Pending traffic bytes conflict with history.")
            stream.seek(offset)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        state["pending_reading"] = None
        self._write_unlocked("router_traffic_v2.json", state)

    def commit_traffic(self, updater: Callable) -> dict[str, Any]:
        """Commit nonce/baseline and a recoverable history append under one lock.

        The callback receives current registry/settings snapshots, so a
        concurrent disable or interface/key change cannot authorize stale data.
        No callback may acquire storage locks or perform external I/O.
        """
        with self._locked():
            state = self._read_unlocked("router_traffic_v2.json")
            self._flush_pending_traffic_unlocked(state)
            state, reading = updater(
                state, self._read_unlocked("routers.json"),
                self._read_unlocked("automation_settings.json"),
            )
            if reading is not None:
                self._validate_traffic(reading)
                encoded = self._traffic_bytes(reading)
                relative, offset = self._traffic_target_unlocked(reading, len(encoded))
                state["pending_reading"] = {"file": relative, "offset": offset, "reading": reading}
            self._write_unlocked("router_traffic_v2.json", state)
            self._flush_pending_traffic_unlocked(state)
            return deepcopy(state)

    def list_traffic(self, limit: int = 100) -> list[dict[str, Any]]:
        """Read recent segments with bounded memory, returning append order."""
        self._limit(limit)
        with self._locked():
            manifest = self._read_unlocked("traffic_history.json")
            result: list[dict[str, Any]] = []
            for entry in reversed(manifest["segments"]):
                with self._segment_path(entry["file"]).open("rb") as stream:
                    lines = deque(stream, maxlen=limit - len(result))
                values = []
                for line in lines:
                    if not line.endswith(b"\n"):
                        raise StorageError("Traffic segment has an incomplete final record.")
                    try:
                        value = json.loads(
                            line,
                            parse_constant=self._invalid_constant,
                            object_pairs_hook=self._unique_object,
                        )
                    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
                        raise StorageError("Traffic segment contains invalid JSON.") from exc
                    self._validate_traffic(value)
                    values.append(value)
                result = values + result
                if len(result) >= limit:
                    break
            return result

    def read_router_config(self, router_id: str) -> dict[str, Any] | None:
        _text(router_id, "Router ID", 128)
        commands = self.read_json("router_config.json")["commands"]
        return next((command for command in commands if command["router_id"] == router_id), None)

    def _workflow_inputs_unlocked(self) -> dict[str, Any]:
        return {name: self._read_unlocked(name) for name in (
            "routers.json", "routing_paths.json", "automation_settings.json", "router_traffic_v2.json",
        )}

    def read_workflow_snapshot(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Read consistent inputs/results without collecting or writing anything."""
        with self._locked():
            return self._workflow_inputs_unlocked(), self._read_unlocked("optimization_results.json")

    def _traffic_windows_unlocked(self, state: dict[str, Any], count: int) -> dict[str, list]:
        """Find the latest readings in each current counter series.

        Inspect at most one bounded segment in memory and stop as soon as
        every series has its window. Legacy history remains untouched.
        """
        targets = {router_id: record for router_id, record in state["routers"].items()
                   if record.get("series_id") and record["sample_state"] == "measured"}
        windows = {router_id: [] for router_id in targets}
        if not targets:
            return windows
        manifest = self._read_unlocked("traffic_history.json")
        for entry in sorted(manifest["segments"], key=lambda item: (item["date"], item["file"]), reverse=True):
            path = self._segment_path(entry["file"])
            if path.stat().st_size > _MAX_SEGMENT_BYTES:
                raise StorageError("Traffic segment exceeds its size limit.")
            for line in reversed(path.read_bytes().splitlines(keepends=True)):
                if not line.endswith(b"\n"):
                    raise StorageError("Traffic segment has an incomplete final record.")
                try:
                    row = json.loads(line, parse_constant=self._invalid_constant,
                                     object_pairs_hook=self._unique_object)
                except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
                    raise StorageError("Traffic segment contains invalid JSON.") from exc
                self._validate_traffic(row)
                router_id = row["router_id"]
                target = targets.get(router_id)
                if (target and len(windows[router_id]) < count
                        and row.get("series_id") == target["series_id"]
                        and row["interface"] == target["interface"]):
                    windows[router_id].append({key: row[key] for key in (
                        "timestamp", "tx_mbps", "tx_octets", "interval_seconds", "request_id",
                    )})
            if all(len(rows) >= count for rows in windows.values()):
                break
        return {router_id: list(reversed(rows)) for router_id, rows in windows.items()}

    def calculate_workflow(self, calculate: Callable) -> dict[str, Any]:
        """Publish a calculation after its average/cost projections are durable.

        The result is the commit record. Orphan projections from an interrupted
        calculation are ignored by readers and replaced on an identical retry.
        Device state, router output, credentials and routing settings are not written.
        """
        with self._locked():
            inputs = self._workflow_inputs_unlocked()
            self._flush_pending_traffic_unlocked(inputs["router_traffic_v2.json"])
            results = self._read_unlocked("optimization_results.json")
            windows = self._traffic_windows_unlocked(
                inputs["router_traffic_v2.json"], inputs["automation_settings.json"]["averaging_window"] + 1,
            )
            result = calculate(inputs, windows, results)
            existing = next((row for row in reversed(results) if row.get("workflow_version") == 1), None)
            if existing is not None and existing["evaluation_id"] == result["evaluation_id"]:
                return deepcopy(existing)
            for name, records in (("averages.json", result["analysis"]),
                                  ("routing_costs.json", result["allocations"])):
                previous = self._read_unlocked(name)
                projection = [{"workflow_version": 1, "evaluation_id": result["evaluation_id"],
                               "calculated_at": result["timestamp"], **row} for row in records]
                self._write_unlocked(name, [row for row in previous
                    if row.get("evaluation_id") != result["evaluation_id"]] + projection)
            self._write_unlocked("optimization_results.json", [*results, result])
            return deepcopy(result)

    def write_router_config(self, command: dict[str, Any]) -> None:
        self._validate_command(command)

        def upsert(document: dict[str, Any]) -> dict[str, Any]:
            document["commands"] = [item for item in document["commands"] if item["router_id"] != command["router_id"]]
            document["commands"].append(command)
            return document

        self.update_json("router_config.json", upsert)

    @staticmethod
    def _validate_traffic(reading: Any) -> None:
        if not isinstance(reading, dict):
            raise ValidationError("Traffic readings must be JSON objects.")
        for key in ("router_id", "interface"):
            _text(reading.get(key), key, 128)
        _timestamp(reading.get("timestamp"))
        value = reading.get("tx_mbps")
        try:
            valid_number = type(value) in (int, float) and math.isfinite(value) and value >= 0
        except OverflowError:
            valid_number = False
        if not valid_number:
            raise ValidationError("TX Mbps must be a finite, nonnegative number.")
        if "tx_octets" in reading and (type(reading["tx_octets"]) is not int or not 0 <= reading["tx_octets"] < 2**64):
            raise ValidationError("TX octets must be an unsigned 64-bit integer.")
        if any(not isinstance(key, str) for key in reading):
            raise ValidationError("Traffic field names must be strings.")
        if any(key.lower().startswith("rx") for key in reading):
            raise ValidationError("Only outbound TX metrics are supported.")
        if "series_id" in reading:
            from services.routeros_protocol import _uuid4
            from services.router_protocol import ProtocolError

            try:
                _uuid4(reading["series_id"])
            except ProtocolError as exc:
                raise ValidationError("Invalid traffic series identity.") from exc
            if (type(reading.get("interval_seconds")) is not int
                    or not 1 <= reading["interval_seconds"] <= 3 * 86400
                    or "tx_octets" not in reading or "request_id" not in reading):
                raise ValidationError("A measured series requires counter, interval and request metadata.")
        _encode(reading)

    @staticmethod
    def _validate_command(command: Any) -> None:
        if not isinstance(command, dict):
            raise ValidationError("Router commands must be JSON objects.")
        _encode(command)
        for key in ("router_id", "command_id", "action"):
            _text(command.get(key), key, 128)
        _timestamp(command.get("timestamp"))
        if command.get("schema_version") != 1 or command.get("mode") not in ("simulation", "live"):
            raise ValidationError("Unsupported command version or mode.")
        if command.get("action") not in ("update_routing_configuration", "restore_routing_configuration", "noop"):
            raise ValidationError("Unsupported configuration action.")
        if not isinstance(command.get("configuration"), dict):
            raise ValidationError("Command configuration must be a JSON object.")
        # Output is a transport contract, never a container for authentication.
        def check_secrets(value: Any) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    if any(word in key.lower() for word in ("password", "secret", "credential", "community", "token")):
                        raise ValidationError("Router configuration output must not contain credentials.")
                    check_secrets(item)
            elif isinstance(value, list):
                for item in value:
                    check_secrets(item)

        check_secrets(command)
        _encode(command)

    def _validate(self, name: str, value: Any) -> None:
        self._path(name)
        _encode(value)
        if name == "automation_settings.json":
            if not isinstance(value, dict) or value.get("schema_version") != 1:
                raise ValidationError("Invalid automation settings document.")
            # Preserve the saved mode; startup must never silently enable live mode.
            if value.get("mode") not in ("live", "simulation") or value.get("automation") != "off" or value.get("routing_changes_enabled") is not False:
                raise ValidationError("Commissioning requires automation off and routing changes disabled.")
            for key in ("monitoring_interval_seconds", "averaging_window"):
                if type(value.get(key)) is not int or not 1 <= value[key] <= 86400:
                    raise ValidationError(f"{key} must be a positive integer no greater than 86400.")
            for key in ("start_time", "stop_time"):
                if value.get(key) is not None and (not isinstance(value[key], str) or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value[key])):
                    raise ValidationError("Schedule times must be HH:MM or null.")
            if value.get("optimization_objective", "not_configured") not in (
                "not_configured", "minimize_cost", "balance_utilization",
            ):
                raise ValidationError("Select a supported dry-run optimization objective.")
        elif name == "traffic_history.json":
            if not isinstance(value, dict) or value.get("schema_version") != 1 or value.get("storage") != "segmented_jsonl" or not isinstance(value.get("segments"), list):
                raise ValidationError("Invalid traffic history manifest.")
            files = []
            for segment in value["segments"]:
                if not isinstance(segment, dict) or not isinstance(segment.get("date"), str):
                    raise ValidationError("Invalid traffic segment metadata.")
                self._segment_path(segment.get("file"))
                if not segment["file"].startswith(f"traffic_segments/traffic-{segment['date']}-"):
                    raise ValidationError("Traffic segment date does not match its path.")
                files.append(segment["file"])
            if len(files) != len(set(files)):
                raise ValidationError("Traffic segment references must be unique.")
        elif name == "routing_paths.json":
            from services.path_config_service import validate_routing_paths

            validate_routing_paths(value)
        elif name == "router_communication.json":
            from services.router_communication_state import validate_communication_state

            validate_communication_state(value)
        elif name == "router_communication_v2.json":
            from services.routeros_poll_service import validate_routeros_state

            validate_routeros_state(value)
        elif name == "router_traffic_v2.json":
            from services.traffic_state import validate_traffic_state

            validate_traffic_state(value)
        elif name == "router_config.json":
            if not isinstance(value, dict) or value.get("schema_version") != 1 or not isinstance(value.get("commands"), list):
                raise ValidationError("Invalid router output envelope.")
            ids = []
            for command in value["commands"]:
                self._validate_command(command)
                ids.append(command["router_id"])
            if len(ids) != len(set(ids)):
                raise ValidationError("Each router must have only one current command.")
        else:
            if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
                raise ValidationError("Record documents must contain a list of JSON objects.")
            if name == "routers.json":
                ids = []
                for router in value:
                    _text(router.get("router_id"), "Router ID", 128)
                    ids.append(router["router_id"])
                if len(ids) != len(set(ids)):
                    raise ValidationError("Router IDs must be unique.")
            elif name == "activity_logs.json":
                for event in value:
                    for key in ("category", "message"):
                        _text(event.get(key), key)
                    _timestamp(event.get("timestamp"))
            elif name in ("optimization_results.json", "averages.json", "routing_costs.json"):
                from services.workflow_state import validate_workflow_projection, validate_workflow_result

                for record in value:
                    if "workflow_version" in record:
                        if name == "optimization_results.json":
                            validate_workflow_result(record)
                        else:
                            validate_workflow_projection(record, name)
