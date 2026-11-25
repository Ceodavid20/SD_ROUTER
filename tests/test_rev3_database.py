"""Private DB client behavior without needing an external server."""
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from services.rev3_database import DatabaseError, MySQLStaging


@pytest.fixture
def client(tmp_path, monkeypatch):
    binary = tmp_path / "mysql"
    binary.write_text("test placeholder, never executed")
    binary.chmod(0o700)
    socket = tmp_path / "mysql.sock"
    socket.touch()
    options = tmp_path / "client.cnf"
    options.write_text("[client]\nuser=synthetic-private-user\npassword=synthetic-private-password\nsocket=" + str(socket) + "\n")
    options.chmod(0o600)
    monkeypatch.setattr("services.rev3_database.stat.S_ISSOCK", lambda mode: True)
    return MySQLStaging(binary, options, "sdr"), binary, options


def test_private_connection_values_never_enter_argv_or_errors(client, monkeypatch):
    database, _, _ = client
    observed = {}
    monkeypatch.setenv("MYSQL_PWD", "synthetic-ambient-password")
    def execute(command, **kwargs):
        observed.update(command=command, kwargs=kwargs)
        return CompletedProcess(command, 1, b"", b"synthetic-private-password synthetic-private-user")
    monkeypatch.setattr("services.rev3_database.subprocess.run", execute)
    with pytest.raises(DatabaseError) as error:
        database.execute("SELECT 1;")
    assert "synthetic-private" not in str(error.value)
    assert "synthetic-private" not in " ".join(observed["command"])
    assert "MYSQL_PWD" not in observed["kwargs"]["env"]
    assert "--force" not in observed["command"]
    assert "--protocol=SOCKET" in observed["command"]


@pytest.mark.parametrize("database", ["mysql", "sys", "information_schema", "performance_schema", "test", "sdr;DROP DATABASE sdr", "../sdr", ""])
def test_database_identifier_cannot_select_system_schema_or_inject_sql(client, database):
    _, binary, options = client
    with pytest.raises(DatabaseError):
        MySQLStaging(binary, options, database)


@pytest.mark.parametrize("damage", ["public", "symlink", "unknown_option", "extra_section"])
def test_options_file_is_private_and_cannot_inject_client_commands(client, tmp_path, damage):
    _, binary, options = client
    if damage == "public":
        options.chmod(0o644)
    elif damage == "symlink":
        alias = tmp_path / "alias.cnf"
        alias.symlink_to(options)
        options = alias
    elif damage == "unknown_option":
        with options.open("a") as stream:
            stream.write("init-command=DROP DATABASE sdr\n")
    else:
        with options.open("a") as stream:
            stream.write("[mysql]\ninit-command=DROP DATABASE sdr\n")
    with pytest.raises(DatabaseError):
        MySQLStaging(binary, options, "sdr")


def test_initialization_cannot_overwrite_existing_database(client, monkeypatch):
    database, _, _ = client
    statements = []
    def execute(sql=None, **kwargs):
        statements.append(sql)
        if sql and "VERSION()" in sql:
            return "10.4.28-MariaDB\tsdr\t1048576\n"
        if sql and "information_schema.tables" in sql:
            return "existing_customer_table\n"
        pytest.fail("Attempted to mutate a nonempty database")
    monkeypatch.setattr(database, "execute", execute)
    with pytest.raises(DatabaseError):
        database.initialize()
    assert len(statements) == 2


@pytest.mark.parametrize("version", ["5.7.44", "8.0.15", "10.1.48-MariaDB"])
def test_unsupported_engine_cannot_skip_cost_safety_constraints(client, monkeypatch, version):
    database, _, _ = client
    monkeypatch.setattr(database, "execute", lambda *a, **k: version + "\tsdr\t1048576\n")
    with pytest.raises(DatabaseError):
        database.info()
