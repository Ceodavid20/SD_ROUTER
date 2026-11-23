"""Test local provisioning and TLS generation without changing a live router."""

from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address
import json
import multiprocessing
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import threading

from dotenv import dotenv_values
import pytest
from werkzeug.security import check_password_hash

from manage import configure_admin
from services.env_storage import update_private_environment
import services.controller_setup_service as setup
from services.controller_setup_service import (
    create_controller_tls, provision_router, render_routeros_script, revoke_router_key,
)
from services.json_storage import StorageService


@pytest.fixture
def store(tmp_path):
    storage = StorageService(tmp_path / "data", tmp_path / "output")
    storage.initialize()
    storage.write_json("routers.json", [{
        "router_id": "TEST-PROVISION-R1", "name": "Test router",
        "controller_auth_ref": "TEST_POLL_R1", "controller_auth_enabled": False,
        "controller_auth_key_ids": [], "interface_name": "test-only-uplink",
    }])
    return storage


@pytest.fixture
def env_file(tmp_path):
    path = tmp_path / ".env"
    path.write_text("# Existing company settings\nUNRELATED_TEST_SETTING='preserve-this-test-value'\n")
    path.chmod(0o600)
    return path


def provision(store, env_file, target, **changes):
    return provision_router(
        store, env_file, "TEST-PROVISION-R1", "https://controller.example.test:18443",
        target, key_id=changes.pop("key_id", "PRIMARY"), **changes,
    )


def test_provisioning_preserves_environment_and_never_returns_or_logs_secret(store, env_file, tmp_path):
    result = provision(store, env_file, tmp_path / "client")
    values = dotenv_values(env_file, interpolate=False)
    secret = values["TEST_POLL_R1_PRIMARY_SECRET"]
    assert re.fullmatch(r"[0-9a-f]{64}", secret)
    assert values["UNRELATED_TEST_SETTING"] == "preserve-this-test-value"
    assert "# Existing company settings" in env_file.read_text()
    record = store.read_json("routers.json")[0]
    assert record["controller_auth_enabled"] is True
    assert record["controller_auth_key_ids"] == ["PRIMARY"]
    assert record["interface_name"] == "test-only-uplink"
    logs = store.read_json("activity_logs.json")
    assert secret not in json.dumps(result)
    assert secret not in json.dumps(record)
    assert secret not in json.dumps(logs)
    assert secret not in (tmp_path / "client" / "connection.json").read_text()
    script = (tmp_path / "client" / "controller-poll.rsc").read_text()
    assert secret in script
    assert "__SHARED_SECRET__" not in script
    assert result["mode"] == "dry_run" and result["action"] == "none"
    assert result["protocol_version"] == "2.0"
    assert result["controller_base_url"] == "https://controller.example.test:18443"


def test_generated_private_bundle_and_environment_have_restricted_permissions(store, env_file, tmp_path):
    target = tmp_path / "client"
    provision(store, env_file, target)
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o700
        assert env_file.stat().st_mode & 0o777 == 0o600
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in target.iterdir())
    assert not any(path.suffix in (".key", ".p12", ".pfx") for path in target.iterdir())


def test_key_rotation_keeps_overlap_and_revocation_is_targeted(store, env_file, tmp_path):
    provision(store, env_file, tmp_path / "first")
    provision(store, env_file, tmp_path / "second", key_id="NEXT")
    values = dotenv_values(env_file, interpolate=False)
    assert values["TEST_POLL_R1_PRIMARY_SECRET"] != values["TEST_POLL_R1_NEXT_SECRET"]
    assert store.read_json("routers.json")[0]["controller_auth_key_ids"] == ["PRIMARY", "NEXT"]
    revoke_router_key(store, "TEST-PROVISION-R1", "PRIMARY")
    record = store.read_json("routers.json")[0]
    assert record["controller_auth_key_ids"] == ["NEXT"]
    assert record["controller_auth_enabled"] is True
    revoke_router_key(store, "TEST-PROVISION-R1")
    record = store.read_json("routers.json")[0]
    assert record["controller_auth_key_ids"] == []
    assert record["controller_auth_enabled"] is False


def test_duplicate_key_id_cannot_overwrite_existing_secret(store, env_file, tmp_path):
    provision(store, env_file, tmp_path / "first")
    before_env = env_file.read_bytes()
    before_registry = deepcopy(store.read_json("routers.json"))
    with pytest.raises(ValueError):
        provision(store, env_file, tmp_path / "duplicate")
    assert env_file.read_bytes() == before_env
    assert store.read_json("routers.json") == before_registry


def test_duplicate_existing_active_ids_cannot_receive_a_new_credential(store, env_file, tmp_path):
    records = store.read_json("routers.json")
    records[0].update(controller_auth_key_ids=["OLD", "OLD"], controller_auth_enabled=True)
    store.write_json("routers.json", records)
    before_env = env_file.read_bytes()
    with pytest.raises(ValueError, match="invalid active key metadata"):
        provision(store, env_file, tmp_path / "invalid-active-keys")
    assert store.read_json("routers.json") == records
    assert env_file.read_bytes() == before_env
    assert not (tmp_path / "invalid-active-keys").exists()


@pytest.mark.parametrize("override", ["", "b" * 64])
def test_process_environment_override_cannot_shadow_a_new_router_secret(
    store, env_file, tmp_path, monkeypatch, override,
):
    monkeypatch.setenv("TEST_POLL_R1_PRIMARY_SECRET", override)
    before_registry = deepcopy(store.read_json("routers.json"))
    before_env = env_file.read_bytes()
    with pytest.raises(ValueError, match="environment override"):
        provision(store, env_file, tmp_path / "shadowed-client")
    assert store.read_json("routers.json") == before_registry
    assert env_file.read_bytes() == before_env
    assert os.environ["TEST_POLL_R1_PRIMARY_SECRET"] == override


def test_revoked_key_id_cannot_reuse_or_overwrite_old_secret(store, env_file, tmp_path):
    provision(store, env_file, tmp_path / "first")
    revoke_router_key(store, "TEST-PROVISION-R1", "PRIMARY")
    before_env = env_file.read_bytes()
    before_registry = deepcopy(store.read_json("routers.json"))
    with pytest.raises(ValueError, match="already has a secret"):
        provision(store, env_file, tmp_path / "reused-key")
    assert env_file.read_bytes() == before_env
    assert store.read_json("routers.json") == before_registry


def test_existing_client_directory_is_never_overwritten(store, env_file, tmp_path):
    target = tmp_path / "existing-client"
    target.mkdir()
    original = target / "controller-poll.rsc"
    original.write_text("existing private client must be preserved")
    before_env = env_file.read_bytes()
    before_registry = deepcopy(store.read_json("routers.json"))
    with pytest.raises(FileExistsError):
        provision(store, env_file, target)
    assert original.read_text() == "existing private client must be preserved"
    assert list(target.iterdir()) == [original]
    assert env_file.read_bytes() == before_env
    assert store.read_json("routers.json") == before_registry


def test_secret_write_failure_never_enables_router_authorization(store, env_file, tmp_path, monkeypatch):
    before_registry = deepcopy(store.read_json("routers.json"))
    before_env = env_file.read_bytes()

    def fail_secret_write(*args, **kwargs):
        raise OSError("simulated private storage unavailable")

    monkeypatch.setattr(setup, "_store_secret", fail_secret_write)
    with pytest.raises(OSError, match="private storage unavailable"):
        provision(store, env_file, tmp_path / "unissued-client")
    assert env_file.read_bytes() == before_env
    assert store.read_json("routers.json") == before_registry
    assert not any(
        event.get("message") == "Router controller credential provisioned."
        for event in store.read_json("activity_logs.json")
    )


def test_concurrent_router_provisioning_and_admin_setup_preserve_all_credentials(store, env_file, tmp_path):
    router_ids = [f"TEST-CONCURRENT-R{index}" for index in range(6)]
    store.write_json("routers.json", [
        {"router_id": router_id, "name": f"Test router {index}",
         "controller_auth_ref": f"TEST_CONCURRENT_{index}",
         "controller_auth_enabled": False, "controller_auth_key_ids": []}
        for index, router_id in enumerate(router_ids)
    ])
    start = threading.Barrier(len(router_ids) + 1)
    password = "test-only-concurrent-administrator-password"

    def issue(index, router_id):
        start.wait(timeout=10)
        return provision_router(
            store, env_file, router_id, "https://controller.example.test",
            tmp_path / f"concurrent-client-{index}", key_id="PRIMARY",
        )

    def administrator():
        start.wait(timeout=10)
        configure_admin(env_file, "concurrentadmin", password)

    with ThreadPoolExecutor(max_workers=len(router_ids) + 1) as pool:
        futures = [pool.submit(issue, index, router_id) for index, router_id in enumerate(router_ids)]
        futures.append(pool.submit(administrator))
        for future in futures:
            future.result(timeout=30)

    values = dotenv_values(env_file, interpolate=False)
    assert values["UNRELATED_TEST_SETTING"] == "preserve-this-test-value"
    assert "# Existing company settings" in env_file.read_text()
    assert values["SDR_ADMIN_USERNAME"] == "concurrentadmin"
    assert check_password_hash(values["SDR_ADMIN_PASSWORD_HASH"], password)
    assert len(values["SDR_SECRET_KEY"]) >= 32
    for index, router_id in enumerate(router_ids):
        secret = values[f"TEST_CONCURRENT_{index}_PRIMARY_SECRET"]
        assert re.fullmatch(r"[0-9a-f]{64}", secret)
        assert secret in (tmp_path / f"concurrent-client-{index}" / "controller-poll.rsc").read_text()
        record = next(item for item in store.read_json("routers.json") if item["router_id"] == router_id)
        assert record["controller_auth_enabled"] is True
        assert record["controller_auth_key_ids"] == ["PRIMARY"]


def _process_environment_update(path, name, started, entered, release):
    """A spawned process has its own thread locks, so this exercises flock."""
    started.set()

    def changes(values):
        entered.set()
        if not release.wait(timeout=15):
            raise RuntimeError("Test environment transaction gate timed out.")
        return {name: "test-only-process-value"}

    update_private_environment(path, changes)


@pytest.mark.skipif(os.name == "nt", reason="The local POSIX deployment uses flock")
def test_private_environment_lock_serializes_distinct_processes(env_file):
    context = multiprocessing.get_context("spawn")
    first_started, second_started = context.Event(), context.Event()
    first_entered, second_entered = context.Event(), context.Event()
    first_release, second_release = context.Event(), context.Event()
    second_release.set()
    first = context.Process(target=_process_environment_update, args=(
        env_file, "FIRST_PROCESS", first_started, first_entered, first_release,
    ))
    second = context.Process(target=_process_environment_update, args=(
        env_file, "SECOND_PROCESS", second_started, second_entered, second_release,
    ))
    try:
        first.start()
        assert first_entered.wait(timeout=10)
        second.start()
        assert second_started.wait(timeout=10)
        assert not second_entered.wait(timeout=0.25)
        first_release.set()
        first.join(timeout=15)
        second.join(timeout=15)
        assert first.exitcode == 0 and second.exitcode == 0
        assert second_entered.is_set()
    finally:
        first_release.set()
        for process in (first, second):
            if process.pid is not None:
                process.join(timeout=2)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
    values = dotenv_values(env_file, interpolate=False)
    assert values["FIRST_PROCESS"] == "test-only-process-value"
    assert values["SECOND_PROCESS"] == "test-only-process-value"
    assert values["UNRELATED_TEST_SETTING"] == "preserve-this-test-value"


@pytest.mark.parametrize("writer", ["router", "administrator"])
def test_environment_writers_reject_symbolic_lock_file(env_file, tmp_path, writer):
    if os.name == "nt":
        pytest.skip("Symbolic-link permission test is POSIX-specific")
    protected = tmp_path / "unrelated-file"
    protected.write_text("must not be opened or replaced")
    lock_path = env_file.with_name(env_file.name + ".lock")
    lock_path.symlink_to(protected)
    before = env_file.read_bytes()
    with pytest.raises(ValueError, match="symbolic"):
        if writer == "router":
            setup._store_secret(env_file, "TEST_ROUTER_SECRET", "a" * 64)
        else:
            configure_admin(env_file, "testadmin", "test-only-administrator-password")
    assert env_file.read_bytes() == before
    assert protected.read_text() == "must not be opened or replaced"
    assert lock_path.is_symlink()


def test_unknown_router_is_not_self_registered(store, env_file, tmp_path):
    before = deepcopy(store.read_json("routers.json"))
    before_env = env_file.read_bytes()
    with pytest.raises(ValueError):
        provision_router(store, env_file, "UNKNOWN-TEST-ROUTER", "https://controller.example.test",
                         tmp_path / "unknown", key_id="PRIMARY")
    assert store.read_json("routers.json") == before
    assert env_file.read_bytes() == before_env
    assert not (tmp_path / "unknown").exists()


@pytest.mark.parametrize("base_url", [
    "http://controller.example.test", "ftp://controller.example.test",
    "https://user:do-not-expose@controller.example.test",
    "https://controller.example.test?secret=do-not-expose",
    "https://controller.example.test#fragment", "https://controller.example.test/prefix",
    "https://controller.example.test:invalid", "https://0.0.0.0:18443",
])
def test_provisioning_rejects_invalid_or_unprotected_origin_without_mutation(store, env_file, tmp_path, base_url):
    before_registry = deepcopy(store.read_json("routers.json"))
    before_env = env_file.read_bytes()
    with pytest.raises(ValueError) as error:
        provision_router(store, env_file, "TEST-PROVISION-R1", base_url, tmp_path / "invalid",
                         key_id="PRIMARY")
    assert "do-not-expose" not in str(error.value)
    assert store.read_json("routers.json") == before_registry
    assert env_file.read_bytes() == before_env
    assert not (tmp_path / "invalid").exists()


def test_rendered_client_is_restricted_and_has_no_unresolved_placeholder():
    secret = "a" * 64
    script = render_routeros_script("TEST-PROVISION-R1", "PRIMARY", secret,
                                    "https://controller.example.test:18443")
    assert "__SHARED_SECRET__" not in script
    assert "__CONTROLLER_BASE_URL__" not in script
    assert not re.search(r"__[A-Z_]+__", script)
    assert "check-certificate=yes" in script
    assert "http-max-redirect-count=0" in script
    assert "/api/controller/v2/poll" in script and "/api/controller/v2/ack" in script
    assert ":parse" not in script and ":execute" not in script
    assert not re.search(r"/(?:routing|ip/route|interface)/.*\b(?:set|add|remove)\b", script)


@pytest.mark.parametrize("change", [
    {"router_id": "../router"}, {"key_id": "invalid-key"}, {"secret": "weak"},
    {"secret": "A" * 64}, {"base_url": "http://controller.example.test"},
])
def test_renderer_rejects_invalid_metadata(change):
    arguments = {
        "router_id": "TEST-PROVISION-R1", "key_id": "PRIMARY",
        "secret": "a" * 64, "base_url": "https://controller.example.test",
    }
    with pytest.raises(ValueError):
        render_routeros_script(**{**arguments, **change})


def test_reference_change_during_provisioning_cannot_enable_stale_authorization(store, env_file, tmp_path, monkeypatch):
    original_update = store.update_json
    changed = False

    def concurrent_update(name, updater):
        nonlocal changed
        if name == "routers.json" and not changed:
            changed = True
            records = store.read_json("routers.json")
            records[0]["controller_auth_ref"] = "OTHER_AUTH_REFERENCE"
            store.write_json("routers.json", records)
        return original_update(name, updater)

    monkeypatch.setattr(store, "update_json", concurrent_update)
    with pytest.raises(ValueError, match="authorization changed"):
        provision(store, env_file, tmp_path / "stale")
    saved = store.read_json("routers.json")[0]
    assert saved["controller_auth_ref"] == "OTHER_AUTH_REFERENCE"
    assert saved["controller_auth_enabled"] is False
    assert saved["controller_auth_key_ids"] == []


def test_private_key_material_cannot_be_copied_as_router_ca(store, env_file, tmp_path):
    private_file = tmp_path / "not-a-ca.pem"
    private_file.write_text("-----BEGIN CERTIFICATE-----\nnot-a-real-ca\n-----END CERTIFICATE-----\n"
                            "-----BEGIN PRIVATE KEY-----\ntest-only-key\n-----END PRIVATE KEY-----")
    before = deepcopy(store.read_json("routers.json"))
    before_env = env_file.read_bytes()
    with pytest.raises(ValueError, match="public"):
        provision(store, env_file, tmp_path / "unsafe-ca", ca_file=private_file)
    assert store.read_json("routers.json") == before
    assert env_file.read_bytes() == before_env
    assert not (tmp_path / "unsafe-ca").exists()


def test_symlink_private_output_or_environment_is_rejected(store, env_file, tmp_path):
    if os.name == "nt":
        pytest.skip("Symbolic-link permission test is POSIX-specific")
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic"):
        provision(store, env_file, link / "bundle")
    env_link = tmp_path / "linked.env"
    env_link.symlink_to(env_file)
    before = env_file.read_bytes()
    with pytest.raises(ValueError, match="symbolic"):
        provision(store, env_link, tmp_path / "linked-env-bundle")
    assert env_file.read_bytes() == before
    assert store.read_json("routers.json")[0]["controller_auth_enabled"] is False


@pytest.mark.parametrize("kwargs", [
    {"allowed_sources": None},
    {"allowed_sources": []},
    {"allowed_sources": ["0.0.0.0/0"]},
    {"allowed_sources": ["::/0"]},
    {"allowed_sources": ["127.0.0.1/32"], "listen_address": "0.0.0.0"},
    {"allowed_sources": ["127.0.0.1/32"], "listen_address": "::"},
    {"allowed_sources": ["127.0.0.1/32"], "port": 443},
    {"allowed_sources": ["127.0.0.1/32"], "hostname": "*.example.test"},
])
def test_tls_setup_rejects_unrestricted_or_invalid_configuration_before_writing(tmp_path, kwargs):
    arguments = {"hostname": "localhost", "output_dir": tmp_path / "invalid-tls"}
    with pytest.raises(ValueError):
        create_controller_tls(**{**arguments, **kwargs})
    assert not (tmp_path / "invalid-tls").exists()


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory):
    if not shutil.which("openssl") or not Path("/usr/libexec/apache2").is_dir():
        pytest.skip("Native Apache/OpenSSL TLS generator is supported on the audited macOS host")
    directory = tmp_path_factory.mktemp("controller-tls").resolve() / "private"
    summary = create_controller_tls(
        "localhost", directory, listen_address="127.0.0.1", port=18443,
        backend_port=8001, allowed_sources=["127.0.0.1/32"],
        additional_hosts=["127.0.0.1", "::1"],
    )
    return directory, summary


def test_tls_generation_produces_valid_public_chain_and_sans_without_starting_listener(tls_material):
    directory, summary = tls_material
    assert summary["network_listener_started"] is False
    checked = subprocess.run(
        [shutil.which("openssl"), "verify", "-CAfile", str(directory / "ca.pem"), str(directory / "server.pem")],
        capture_output=True, text=True, check=False,
    )
    assert checked.returncode == 0
    certificate = ssl._ssl._test_decode_cert(str(directory / "server.pem"))
    alternatives = certificate["subjectAltName"]
    assert ("DNS", "localhost") in alternatives
    addresses = {ip_address(value) for kind, value in alternatives if kind == "IP Address"}
    assert ip_address("127.0.0.1") in addresses and ip_address("::1") in addresses
    assert "PRIVATE KEY" not in json.dumps(summary)
    if os.name != "nt":
        assert directory.stat().st_mode & 0o777 == 0o700
        for path in directory.iterdir():
            assert path.stat().st_mode & 0o777 == 0o600
    config = (directory / "httpd.conf").read_text()
    assert "SSLProtocol -all +TLSv1.2" in config
    assert "Require ip 127.0.0.1/32" in config
    assert 'Require all denied' in config
    assert 'ProxyRequests Off' in config
    assert 'Listen 127.0.0.1:18443' in config
    # The unprivileged listener must not try to create its proxy mutexes in
    # the system-wide /private/var/run directory.
    assert f'DefaultRuntimeDir "{directory}"' in config
    syntax = subprocess.run(["/usr/sbin/httpd", "-t", "-f", str(directory / "httpd.conf")],
                            capture_output=True, check=False)
    assert syntax.returncode == 0


def _strict_memory_handshake(directory, hostname):
    """Exchange real TLS records in memory, without binding a TCP socket."""
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = server_context.maximum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(directory / "server.pem", directory / "server.key")
    client_context = ssl.create_default_context(cafile=directory / "ca.pem")
    client_context.verify_flags |= ssl.VERIFY_X509_STRICT
    client_context.minimum_version = client_context.maximum_version = ssl.TLSVersion.TLSv1_2
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(client_in, client_out, server_hostname=hostname)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    finished = [False, False]
    for _ in range(20):
        for index, endpoint, outgoing, incoming in (
            (0, client, client_out, server_in), (1, server, server_out, client_in),
        ):
            if not finished[index]:
                try:
                    endpoint.do_handshake()
                    finished[index] = True
                except ssl.SSLWantReadError:
                    pass
            data = outgoing.read()
            if data:
                incoming.write(data)
        if all(finished):
            return client
    pytest.fail("In-memory TLS handshake did not finish.")


def test_generated_certificates_pass_strict_real_tls_verification(tls_material):
    directory, _ = tls_material
    client = _strict_memory_handshake(directory, "localhost")
    assert client.version() == "TLSv1.2"
    assert ("DNS", "localhost") in client.getpeercert()["subjectAltName"]


def test_generated_certificate_rejects_an_unlisted_controller_hostname(tls_material):
    directory, _ = tls_material
    with pytest.raises(ssl.SSLCertVerificationError):
        _strict_memory_handshake(directory, "wrong-controller.example.test")


def test_router_bundle_copies_only_public_ca(store, env_file, tmp_path, tls_material):
    directory, _ = tls_material
    summary = provision(store, env_file, tmp_path / "client-with-ca", ca_file=directory / "ca.pem")
    copied = (tmp_path / "client-with-ca" / summary["ca_file"]).read_bytes()
    assert copied == (directory / "ca.pem").read_bytes()
    assert b"PRIVATE KEY" not in copied
    assert not any(path.suffix == ".key" for path in (tmp_path / "client-with-ca").iterdir())

