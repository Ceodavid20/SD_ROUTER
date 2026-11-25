"""Opt-in real local MySQL/MariaDB tests with isolated test records.

Set SDR_REV3_MYSQL_TEST_OPTIONS and SDR_REV3_MYSQL_TEST_BINARY to owner-only
local client options and its client binary. Uses an already initialized schema.
Never creates/drops a database, modifies credentials or contacts a router.
Transaction tests roll back; round-trip fixtures remove only their own archive.
"""
import os
from uuid import uuid4

import pytest

from services.rev3_database import DatabaseError, MySQLStaging
from services.rev3_migration import prepare
from services.json_storage import StorageService


@pytest.fixture
def database():
    options = os.environ.get("SDR_REV3_MYSQL_TEST_OPTIONS")
    binary = os.environ.get("SDR_REV3_MYSQL_TEST_BINARY")
    if not options or not binary:
        pytest.skip("Real database test is opt-in via private local client options")
    client = MySQLStaging(binary, options, os.environ.get("SDR_REV3_MYSQL_TEST_DATABASE", "sdr"))
    client.check_schema()
    return client


def test_real_engine_uses_innodb_and_enforced_schema(database):
    assert database.execute("SELECT DISTINCT ENGINE FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE();").strip() == "InnoDB"
    assert database.execute("SELECT version FROM sdr_schema_migrations;").strip() == "1"


def batch_sql(identity):
    return ("INSERT INTO sdr_migration_batches (snapshot_id,captured_at,expected_files,traffic_records,state) "
            f"VALUES ('{identity}',UTC_TIMESTAMP(6),1,0,'staged');\n")


def test_explicit_rollback_preserves_existing_archive(database):
    identity = uuid4().hex
    database.execute("START TRANSACTION;\n" + batch_sql(identity) + "ROLLBACK;\n")
    assert database.execute(f"SELECT COUNT(*) FROM sdr_migration_batches WHERE snapshot_id='{identity}';").strip() == "0"


def test_interrupted_duplicate_import_rolls_back_all_prior_inserts(database):
    identity = uuid4().hex
    with pytest.raises(DatabaseError):
        database.execute("START TRANSACTION;\n" + batch_sql(identity) + batch_sql(identity) + "COMMIT;\n")
    assert database.execute(f"SELECT COUNT(*) FROM sdr_migration_batches WHERE snapshot_id='{identity}';").strip() == "0"


def test_archive_cannot_be_marked_active(database):
    identity = uuid4().hex
    with pytest.raises(DatabaseError):
        database.execute("START TRANSACTION;\n" + batch_sql(identity).replace("'staged'", "'active'") + "COMMIT;\n")
    assert database.execute(f"SELECT COUNT(*) FROM sdr_migration_batches WHERE snapshot_id='{identity}';").strip() == "0"


def test_chunk_length_constraint_and_transaction_rollback(database):
    identity = uuid4().hex
    sql = batch_sql(identity)
    sql += ("INSERT INTO sdr_migration_files (snapshot_id,file_name,byte_count,sha256,expected_chunks) "
            f"VALUES ('{identity}','synthetic.json',1,REPEAT('a',64),1);\n")
    sql += ("INSERT INTO sdr_migration_chunks (snapshot_id,file_name,chunk_number,byte_count,sha256,payload) "
            f"VALUES ('{identity}','synthetic.json',0,2,REPEAT('a',64),X'01');\n")
    with pytest.raises(DatabaseError):
        database.execute("START TRANSACTION;\n" + sql + "COMMIT;\n")
    assert database.execute(f"SELECT COUNT(*) FROM sdr_migration_batches WHERE snapshot_id='{identity}';").strip() == "0"


def test_ospf_cost_bounds_enforced_by_real_database(database):
    identity = uuid4().hex
    sql = f"INSERT INTO sdr_routers (router_id,display_name,created_at) VALUES ('{identity}','Synthetic integration router',UTC_TIMESTAMP(6));\n"
    sql += f"INSERT INTO sdr_link_pairs (pair_id,display_name,site_a,site_b) VALUES ('{identity}','Synthetic pair','Site A','Site B');\n"
    sql += ("INSERT INTO sdr_links (link_id,pair_id,router_id,tx_interface,minimum_cost,normal_cost,maximum_cost) "
            f"VALUES ('{identity}','{identity}','{identity}','synthetic-tx',10,5,20);\n")
    with pytest.raises(DatabaseError):
        database.execute("START TRANSACTION;\n" + sql + "COMMIT;\n")
    assert database.execute(f"SELECT COUNT(*) FROM sdr_routers WHERE router_id='{identity}';").strip() == "0"


def test_default_monitoring_is_disabled_and_unknown_link_capacity_is_preserved(database):
    identity = uuid4().hex
    sql = f"INSERT INTO sdr_routers (router_id,display_name,created_at) VALUES ('{identity}','Synthetic integration router',UTC_TIMESTAMP(6));\n"
    sql += f"INSERT INTO sdr_link_pairs (pair_id,display_name,site_a,site_b) VALUES ('{identity}','Synthetic pair','Site A','Site B');\n"
    sql += f"INSERT INTO sdr_links (link_id,pair_id,router_id,tx_interface) VALUES ('{identity}','{identity}','{identity}','synthetic-tx');\n"
    sql += f"SELECT monitoring_enabled FROM sdr_routers WHERE router_id='{identity}';\n"
    sql += f"SELECT capacity_bps IS NULL AND normal_cost IS NULL FROM sdr_links WHERE link_id='{identity}';\n"
    result = database.execute("START TRANSACTION;\n" + sql + "ROLLBACK;\n")
    assert result.splitlines() == ["0", "1"]
    assert database.execute(f"SELECT COUNT(*) FROM sdr_routers WHERE router_id='{identity}';").strip() == "0"


@pytest.fixture
def imported_archive(database, tmp_path):
    tmp_path.chmod(0o700)
    config = {"ENVIRONMENT": "development", "DATA_DIR": tmp_path / "data", "OUTPUT_DIR": tmp_path / "output",
              "SIMULATION_MODE": True, "LIVE_ROUTING_ENABLED": False}
    storage = StorageService(config["DATA_DIR"], config["OUTPUT_DIR"])
    storage.initialize()
    storage.write_json("routers.json", [{"router_id": "TEST-DATABASE", "name": "SQL ' quotes and Ω"}])
    storage.append_traffic({"router_id": "TEST-DATABASE", "interface": "test-tx", "timestamp": "2026-11-25T08:00:00Z",
                            "tx_octets": 2**64 - 1, "tx_mbps": 0.25})
    bundle = tmp_path / "bundle"
    manifest = prepare(config, bundle)
    identity = manifest["snapshot_id"]
    try:
        database.import_bundle(bundle)
        yield config, bundle, manifest
    finally:
        # Remove only this fixture's random snapshot, never the operator archive.
        database.execute("START TRANSACTION;\n"
            f"DELETE FROM sdr_migration_chunks WHERE snapshot_id='{identity}';\n"
            f"DELETE FROM sdr_migration_files WHERE snapshot_id='{identity}';\n"
            f"DELETE FROM sdr_migration_batches WHERE snapshot_id='{identity}';\nCOMMIT;\n")


def test_real_database_import_restore_and_duplicate_protection(database, imported_archive, tmp_path):
    config, bundle, manifest = imported_archive
    result = database.verify_import(bundle)
    assert result["runtime_cutover_authorized"] is False
    assert result["counts"]["traffic_records"] == 1
    destination = tmp_path / "database-restore"
    assert database.rehearse_restore(config, bundle, destination)["database_restore_verified"] is True
    for row in manifest["files"]:
        assert (destination / row["name"]).read_bytes() == (bundle / row["name"]).read_bytes()
    with pytest.raises(DatabaseError):
        database.import_bundle(bundle)


def test_corrupted_database_chunk_cannot_verify_or_restore(database, imported_archive, tmp_path):
    config, bundle, manifest = imported_archive
    identity = manifest["snapshot_id"]
    database.execute("UPDATE sdr_migration_chunks SET payload=CONCAT(SUBSTRING(payload,1,byte_count-1),X'FF') "
        f"WHERE snapshot_id='{identity}' AND file_name='data/routers.json' AND chunk_number=0;")
    with pytest.raises(DatabaseError):
        database.verify_import(bundle)
    destination = tmp_path / "bad-restore"
    with pytest.raises(DatabaseError):
        database.rehearse_restore(config, bundle, destination)
    assert not destination.exists()
