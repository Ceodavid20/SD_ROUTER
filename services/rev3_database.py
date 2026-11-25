"""Explicit operator-only MySQL staging. Never imported by Flask or its workers.

Private client options avoid credentials in argv, logs, HTML or SQL artifacts.
No database/user creation, grants, drops, truncation, runtime switch or router I/O.
"""
import configparser
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess

from services.rev3_migration import MigrationError, SCHEMA, CHUNK_BYTES, verify, _read, _write, _destination


class DatabaseError(MigrationError):
    pass


class MySQLStaging:
    def __init__(self, binary, options, database):
        self.binary, self.options = Path(binary).absolute(), Path(options).absolute()
        if (not isinstance(database, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", database)
                or database.lower() in {"mysql", "sys", "information_schema", "performance_schema", "test"}):
            raise DatabaseError("Select a dedicated SDR database.")
        self.database = database
        if not self.binary.is_file() or not os.access(self.binary, os.X_OK):
            raise DatabaseError("Select an available local MySQL client binary.")
        if (any(p.is_symlink() for p in (self.options, *self.options.parents))
                or not self.options.is_file() or self.options.stat().st_mode & 0o077
                or self.options.stat().st_size > 16384):
            raise DatabaseError("Use an owner-only bounded client options file.")
        try:
            values = configparser.ConfigParser(interpolation=None, strict=True)
            values.read_string(self.options.read_text())
            if (values.sections() != ["client"] or values.defaults()
                    or set(values["client"]) - {"user", "password", "socket"}
                    or not values["client"].get("user") or not values["client"].get("socket")):
                raise ValueError
            socket = Path(values["client"]["socket"])
            if not socket.is_absolute() or not stat.S_ISSOCK(socket.stat().st_mode):
                raise ValueError
        except (OSError, ValueError, configparser.Error):
            raise DatabaseError("Client options must contain only a local socket and private login settings.") from None

    def execute(self, sql=None, *, script=None):
        if (sql is None) == (script is None):
            raise DatabaseError("Choose one SQL operation.")
        command = [str(self.binary), "--defaults-file=" + str(self.options), "--protocol=SOCKET",
                   "--database=" + self.database, "--batch", "--raw", "--skip-column-names",
                   "--binary-mode", "--default-character-set=utf8mb4", "--connect-timeout=5"]
        environment = {k: v for k, v in os.environ.items() if k not in {"MYSQL_PWD", "MYSQL_TEST_LOGIN_FILE"}}
        session = b"SET SESSION sql_mode='STRICT_ALL_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';\nSET time_zone='+00:00';\n"
        try:
            if script is not None:
                with Path(script).open("rb") as stream:
                    result = subprocess.run(command, stdin=stream, capture_output=True, timeout=180, env=environment)
            else:
                result = subprocess.run(command, input=session + sql.encode("utf-8"), capture_output=True, timeout=30, env=environment)
            if result.returncode:
                # Never echo client stderr: it can contain SQL, credentials or private data.
                raise DatabaseError("Database operation failed; private server details withheld. No automatic cleanup was attempted.")
            return result.stdout.decode("utf-8")
        except (OSError, UnicodeError, subprocess.TimeoutExpired):
            raise DatabaseError("Database unavailable or timed out; private connection details withheld.") from None

    def info(self):
        row = self.execute("SELECT VERSION(),DATABASE(),@@max_allowed_packet;").strip().split("\t")
        if len(row) != 3 or row[1] != self.database:
            raise DatabaseError("Unexpected database identity.")
        match = re.match(r"(\d+)\.(\d+)\.(\d+)", row[0])
        if not match:
            raise DatabaseError("Unsupported database version.")
        version = tuple(map(int, match.groups()))
        maria = "MariaDB" in row[0]
        if (maria and version < (10,4,0)) or (not maria and version < (8,0,16)):
            raise DatabaseError("An engine with enforced CHECK constraints is required.")
        if int(row[2]) < CHUNK_BYTES * 2 + 2048:
            raise DatabaseError("The server packet limit is too small for the bounded staging chunks.")
        return {"engine": "mariadb" if maria else "mysql", "version": row[0], "database": self.database}

    def tables(self):
        return set(self.execute("SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE();").split())

    @staticmethod
    def expected_tables():
        return set(re.findall(r"CREATE TABLE (sdr_[a-z_]+)\s*\(", SCHEMA.read_text()))

    def initialize(self):
        info = self.info()
        if self.tables():
            raise DatabaseError("Schema creation requires an empty dedicated database; existing tables were preserved.")
        self.execute(script=SCHEMA)
        self.check_schema()
        return {**info, "schema_version": 1, "tables": len(self.expected_tables()), "runtime_backend": "json",
                "runtime_cutover_authorized": False, "router_execution_authorized": False}

    def check_schema(self):
        self.info()
        if self.tables() != self.expected_tables() or self.execute("SELECT version FROM sdr_schema_migrations;").strip() != "1":
            raise DatabaseError("The database does not match the Stage 2 schema; no changes were attempted.")

    def import_bundle(self, bundle):
        manifest = verify(bundle)
        self.check_schema()
        identity = manifest["snapshot_id"]
        if self.execute(f"SELECT COUNT(*) FROM sdr_migration_batches WHERE snapshot_id='{identity}';").strip() != "0":
            raise DatabaseError("This snapshot is already present; verify it instead of importing it again.")
        self.execute(script=Path(bundle) / "mysql-import.sql")
        return self.verify_import(bundle)

    def _database_files(self, manifest):
        identity = manifest["snapshot_id"]
        row = self.execute(f"SELECT expected_files,traffic_records,state FROM sdr_migration_batches WHERE snapshot_id='{identity}';").strip().split("\t")
        if row != [str(len(manifest["files"])), str(manifest["counts"]["traffic_records"]), "staged"]:
            raise DatabaseError("Database snapshot metadata does not reconcile.")
        rows = self.execute(f"SELECT file_name,byte_count,sha256,expected_chunks FROM sdr_migration_files WHERE snapshot_id='{identity}' ORDER BY file_name;").splitlines()
        expected = sorted((r["name"], str(r["bytes"]), r["sha256"], str((r["bytes"] + CHUNK_BYTES - 1) // CHUNK_BYTES)) for r in manifest["files"])
        if [tuple(r.split("\t")) for r in rows] != expected:
            raise DatabaseError("Database snapshot file inventory does not reconcile.")
        for row in manifest["files"]:
            name = row["name"]
            digest, size = hashlib.sha256(), 0
            chunks = self.execute(f"SELECT chunk_number,HEX(payload),sha256,byte_count FROM sdr_migration_chunks WHERE snapshot_id='{identity}' AND file_name='{name}' ORDER BY chunk_number;").splitlines()
            if len(chunks) != (row["bytes"] + CHUNK_BYTES - 1) // CHUNK_BYTES:
                raise DatabaseError("Database chunk count does not reconcile.")
            for number, encoded in enumerate(chunks):
                values = encoded.split("\t")
                if len(values) != 4 or values[0] != str(number):
                    raise DatabaseError("Database chunk order does not reconcile.")
                try:
                    raw = bytes.fromhex(values[1])
                except ValueError:
                    raise DatabaseError("Invalid database snapshot bytes.") from None
                if len(raw) != int(values[3]) or not 1 <= len(raw) <= CHUNK_BYTES or hashlib.sha256(raw).hexdigest() != values[2]:
                    raise DatabaseError("Database chunk checksum does not reconcile.")
                digest.update(raw); size += len(raw)
                yield name, raw
            if digest.hexdigest() != row["sha256"] or size != row["bytes"]:
                raise DatabaseError("Database file checksum does not reconcile.")

    def verify_import(self, bundle):
        manifest = verify(bundle)
        self.check_schema()
        for _ in self._database_files(manifest):
            pass
        return {"verified": True, "schema_version": 1, "counts": manifest["counts"],
                "runtime_backend": "json", "runtime_cutover_authorized": False,
                "router_execution_authorized": False}

    def rehearse_restore(self, config, bundle, destination):
        manifest = verify(bundle)
        self.check_schema()
        destination = _destination(config, destination)
        root = Path(bundle).absolute()
        if destination == root or destination.is_relative_to(root) or root.is_relative_to(destination):
            raise DatabaseError("Restore outside the verified bundle.")
        created = False
        try:
            destination.mkdir(mode=0o700)
            created = True
            # Create empty files first; the generator checks exact bytes before success.
            for row in manifest["files"]:
                _write(destination / row["name"], b"")
            for name, raw in self._database_files(manifest):
                with (destination / name).open("ab") as stream:
                    stream.write(raw)
            for row in manifest["files"]:
                if hashlib.sha256(_read(destination / row["name"])).hexdigest() != row["sha256"]:
                    raise DatabaseError("Restored database bytes do not reconcile.")
            (destination / "data/traffic_segments").mkdir(mode=0o700, exist_ok=True)
            _write(destination / "data/.storage.lock", b"")
            return {"database_restore_verified": True, "counts": manifest["counts"], "runtime_cutover_authorized": False}
        except (OSError, ValueError):
            if created:
                import shutil
                shutil.rmtree(destination)
            raise DatabaseError("Database restore rehearsal failed; active storage was not touched.") from None
