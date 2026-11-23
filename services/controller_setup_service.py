"""Local-only provisioning helpers. No router connection or firewall changes.

Secrets are written to private files/environment references, never returned
in JSON or browser pages. The browser has no provisioning route.
"""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
from urllib.parse import urlsplit

from services.controller_connection_service import connection_details
from services.env_storage import update_private_environment
from services.json_storage import StorageService
from services.router_protocol import KEY_ID, ROUTER_ID


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _private_file(path: Path, data: str | bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data.encode() if isinstance(data, str) else data)
        stream.flush()
        os.fsync(stream.fileno())


def _new_private_directory(directory: str | Path) -> Path:
    target = Path(directory).expanduser().absolute()
    if any(character in str(target) for character in ('"', '\\', '\n', '\r', '\0')):
        raise ValueError('Private output paths contain an unsupported character.')
    if any(part.is_symlink() for part in (target, *target.parents)):
        raise ValueError('Private output paths must not contain symbolic links.')
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.mkdir(mode=0o700, exist_ok=False)
    return target


def _https_origin(base_url: str) -> str:
    details = connection_details({'CONTROLLER_BASE_URL': base_url, 'ROUTER_POLL_INTERVAL': 60})
    if details['endpoint_url'] is None or urlsplit(base_url).scheme != 'https':
        raise ValueError('Use a verified HTTPS controller origin without credentials or a path.')
    parts = urlsplit(base_url.strip())
    return f'https://{parts.netloc}'


def _routeros_string(value: str) -> str:
    return value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('\r', '\\r').replace('\n', '\\n')


def render_routeros_script(router_id: str, key_id: str, secret: str, base_url: str) -> str:
    if not isinstance(router_id, str) or not ROUTER_ID.fullmatch(router_id):
        raise ValueError('Invalid registered router identity.')
    if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
        raise ValueError('Invalid controller key ID.')
    if not isinstance(secret, str) or not re.fullmatch(r'[0-9a-f]{64}', secret):
        raise ValueError('RouterOS bundles require a generated 256-bit hexadecimal secret.')
    origin = _https_origin(base_url)
    template = (PROJECT_ROOT / 'scripts/routeros/controller_poll_v2.rsc').read_text()
    values = {'__ROUTER_ID__': router_id, '__KEY_ID__': key_id,
              '__SHARED_SECRET__': secret, '__CONTROLLER_BASE_URL__': origin}
    for placeholder, value in values.items():
        if placeholder not in template:
            raise ValueError('The RouterOS client template is incomplete.')
        template = template.replace(placeholder, _routeros_string(value))
    if re.search(r'__[A-Z_]+__', template):
        raise ValueError('The RouterOS client contains an unresolved setting.')
    return template


def _store_secret(env_path: Path, name: str, value: str) -> None:
    def add_secret(values):
        if values.get(name):
            raise ValueError('That key ID already has a secret. Use a new key ID for rotation.')
        if name in os.environ:
            raise ValueError('That key ID has a process environment override. Use a new key ID for rotation.')
        return {name: value}

    update_private_environment(env_path, add_secret)


def provision_router(
    storage: StorageService, env_path: str | Path, router_id: str,
    base_url: str, output_dir: str | Path, *, key_id: str | None = None,
    ca_file: str | Path | None = None,
) -> dict:
    """Issue a new private client bundle for an existing, approved identity."""
    origin = _https_origin(base_url)
    if not isinstance(router_id, str) or not ROUTER_ID.fullmatch(router_id):
        raise ValueError('Invalid router ID.')
    router = next((r for r in storage.read_json('routers.json') if r['router_id'] == router_id), None)
    if router is None:
        raise ValueError('Router identity is not registered. Provisioning cannot self-register a device.')
    key_id = key_id or ('K' + datetime.now(UTC).strftime('%Y%m%d%H%M%S') + '_' + secrets.token_hex(3).upper())
    if not KEY_ID.fullmatch(key_id):
        raise ValueError('Invalid key ID.')
    reference = router.get('controller_auth_ref') or ('SDR_POLL_' + hashlib.sha256(router_id.encode()).hexdigest()[:16].upper())
    if not isinstance(reference, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', reference):
        raise ValueError('The router authentication reference needs correction.')
    active = router.get('controller_auth_key_ids', [])
    if (not isinstance(active, list)
            or any(not isinstance(k, str) or not KEY_ID.fullmatch(k) for k in active)
            or len(set(active)) != len(active)):
        raise ValueError('The router has invalid active key metadata.')
    if key_id in active:
        raise ValueError('This key ID is already active. Select a new key ID for rotation.')
    secret = secrets.token_hex(32)
    script = render_routeros_script(router_id, key_id, secret, origin)
    ca = Path(ca_file).expanduser().resolve().read_bytes() if ca_file else None
    if ca is not None and (b'-----BEGIN CERTIFICATE-----' not in ca or b'PRIVATE KEY' in ca):
        raise ValueError('Supply only the public controller CA certificate, never a private key.')
    target = _new_private_directory(output_dir)
    _private_file(target / 'controller-poll.rsc', script)
    if ca is not None:
        _private_file(target / 'controller-ca.pem', ca)
    summary = {
        'router_id': router_id, 'key_id': key_id, 'controller_base_url': origin,
        'protocol_version': '2.0', 'mode': 'dry_run', 'action': 'none',
        'script_file': 'controller-poll.rsc', 'ca_file': 'controller-ca.pem' if ca else None,
        'generated_at': datetime.now(UTC).isoformat().replace('+00:00', 'Z'),
    }
    _private_file(target / 'connection.json', json.dumps(summary, indent=2) + '\n')
    _private_file(target / 'README.txt', (
        'PRIVATE ROUTER CLIENT BUNDLE\n'
        'controller-poll.rsc contains this router\'s controller secret. Do not paste or upload it to the website.\n'
        'Restart the device server after provisioning so it loads the new environment reference.\n'
        'Verify controller address, certificate trust, router clock, and permissions before use.\n'
        'Copy only the client script and public CA certificate to the approved router through a trusted channel.\n'
        'Import and trust the public CA only after verifying its fingerprint through that channel.\n'
        'Run the script once manually; confirm authenticated polling and receipt in the controller.\n'
        'This bundle performs no route/interface/OSPF changes. Scheduling is a later explicit installation step.\n'
    ))
    # Write the secret before enabling it. A partial failure leaves an unused
    # key, never an enabled identity whose secret was only partially written.
    _store_secret(Path(env_path).expanduser().absolute(), f'{reference}_{key_id}_SECRET', secret)
    expected_auth = tuple(router.get(k) for k in ('controller_auth_ref', 'controller_auth_key_ids', 'controller_auth_enabled'))

    def enable(routers):
        current = next((r for r in routers if r['router_id'] == router_id), None)
        if current is None or tuple(current.get(k) for k in ('controller_auth_ref', 'controller_auth_key_ids', 'controller_auth_enabled')) != expected_auth:
            raise ValueError('Router authorization changed during provisioning. Review the unused bundle before retrying.')
        current.update(controller_auth_ref=reference, controller_auth_enabled=True,
                       controller_auth_key_ids=[*active, key_id])
        return routers

    storage.update_json('routers.json', enable)
    storage.append_activity('security', 'Router controller credential provisioned.', {'router_id': router_id, 'key_id': key_id})
    return {**summary, 'output_dir': str(target)}


def revoke_router_key(storage: StorageService, router_id: str, key_id: str | None = None) -> None:
    if not isinstance(router_id, str) or not ROUTER_ID.fullmatch(router_id):
        raise ValueError('Invalid router identity.')
    if key_id is not None and not KEY_ID.fullmatch(key_id):
        raise ValueError('Invalid key ID.')

    def revoke(routers):
        current = next((r for r in routers if r['router_id'] == router_id), None)
        if current is None:
            raise ValueError('Router identity is not registered.')
        active = current.get('controller_auth_key_ids', [])
        if not isinstance(active, list):
            raise ValueError('Invalid router authorization metadata.')
        remaining = [k for k in active if k != key_id] if key_id else []
        current.update(controller_auth_key_ids=remaining, controller_auth_enabled=bool(remaining))
        return routers

    storage.update_json('routers.json', revoke)
    storage.append_activity('security', 'Router controller authorization revoked.', {'router_id': router_id})


def create_controller_tls(
    hostname: str, output_dir: str | Path, *, listen_address: str = '127.0.0.1',
    port: int = 18443, backend_port: int = 8001, allowed_sources: list[str] | None = None,
    additional_hosts: list[str] | None = None,
    allow_enrollment: bool = False,
) -> dict:
    """Generate a private CA/server certificate and isolated Apache config.

    This never starts a listener or changes system Apache/firewall settings.
    Apache and OpenSSL are existing operating-system tools, not new services
    installed by this function.
    """
    hosts = [hostname, *(additional_hosts or [])]
    if type(allow_enrollment) is not bool:
        raise ValueError("Enrollment exposure must be explicitly enabled or disabled.")
    sans = []
    for host in hosts:
        if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9:.\-]{1,253}', host):
            raise ValueError('Use an explicit certificate hostname or IP address.')
        try:
            address = ip_address(host)
        except ValueError:
            if ':' in host or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', x) for x in host.split('.')):
                raise ValueError('Invalid certificate hostname.')
            sans.append(('DNS', host))
        else:
            if address.is_unspecified or address.is_multicast:
                raise ValueError('Use a specific certificate address.')
            sans.append(('IP', str(address)))
    listen = ip_address(listen_address)
    if listen.is_unspecified or listen.is_multicast:
        raise ValueError('Bind the TLS listener to one explicitly approved interface address.')
    for value in (port, backend_port):
        if type(value) is not int or not 1024 <= value <= 65535:
            raise ValueError('Use a nonprivileged TCP port between 1024 and 65535.')
    if not allowed_sources:
        raise ValueError('Supply the approved router source addresses or subnets.')
    networks = []
    for source in allowed_sources:
        network = ip_network(source, strict=False)
        if network.prefixlen == 0:
            raise ValueError('An unrestricted source network is not permitted.')
        networks.append(str(network))
    openssl = shutil.which('openssl')
    apache = shutil.which('httpd') or ('/usr/sbin/httpd' if Path('/usr/sbin/httpd').is_file() else None)
    modules = Path('/usr/libexec/apache2')
    if not openssl or not apache or not modules.is_dir():
        raise ValueError('OpenSSL and the existing Apache TLS modules are required on this host.')
    target = _new_private_directory(output_dir)
    ca_name = 'SDR Controller CA ' + secrets.token_hex(4).upper()
    ca_conf = '[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca_ext\n[dn]\nCN=' + ca_name + '\n[ca_ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n'
    san_lines = '\n'.join(f'{kind}.{index}={value}' for index, (kind, value) in enumerate(sans, 1))
    # The CSR cannot refer to an issuer. Apply AKI only when the CA signs
    # the leaf; strict TLS verifiers require it in the issued certificate.
    server_conf = ('[req]\nprompt=no\ndistinguished_name=dn\nreq_extensions=req_ext\n[dn]\nCN=' + hostname +
                   '\n[req_ext]\nsubjectAltName=@alt\n[server_ext]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=@alt\n[alt]\n' + san_lines + '\n')
    _private_file(target / 'ca.cnf', ca_conf)
    _private_file(target / 'server.cnf', server_conf)

    def run(arguments):
        result = subprocess.run([openssl, *arguments], cwd=target, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            raise ValueError('Certificate generation failed. Review the private output directory.')

    run(['req', '-new', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '365', '-config', 'ca.cnf', '-keyout', 'ca.key', '-out', 'ca.pem'])
    run(['req', '-new', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-config', 'server.cnf', '-keyout', 'server.key', '-out', 'server.csr'])
    run(['x509', '-req', '-sha256', '-days', '90', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-extfile', 'server.cnf', '-extensions', 'server_ext', '-out', 'server.pem'])
    for name in ('ca.key', 'server.key', 'ca.pem', 'server.pem', 'ca.srl', 'server.csr'):
        (target / name).chmod(0o600)
    module_names = {
        'mpm_prefork': 'mpm_prefork', 'unixd': 'unixd', 'authz_core': 'authz_core',
        'authz_host': 'authz_host', 'log_config': 'log_config', 'ssl': 'ssl',
        'socache_shmcb': 'socache_shmcb', 'proxy': 'proxy', 'proxy_http': 'proxy_http',
        'headers': 'headers',
    }
    loads = []
    for name, filename in module_names.items():
        module = modules / f'mod_{filename}.so'
        if not module.is_file():
            raise ValueError('An Apache TLS/proxy module is unavailable.')
        loads.append(f'LoadModule {name}_module "{module}"')
    bind = f'[{listen}]' if listen.version == 6 else str(listen)
    name = f'[{hostname}]' if ':' in hostname else hostname
    conf = '\n'.join([
        f'ServerRoot "{target}"', f'DefaultRuntimeDir "{target}"', f'PidFile "{target / "httpd.pid"}"',
        f'Listen {bind}:{port}', f'ServerName {name}:{port}', *loads,
        f'ErrorLog "{target / "error.log"}"', 'LogLevel warn',
        'ServerTokens Prod', 'ServerSignature Off', 'TraceEnable Off',
        'Timeout 15', 'KeepAlive On', 'MaxKeepAliveRequests 20', 'KeepAliveTimeout 3',
        'StartServers 1', 'MinSpareServers 1', 'MaxSpareServers 3', 'MaxRequestWorkers 8',
        f'<VirtualHost {bind}:{port}>', 'SSLEngine on', 'SSLProtocol -all +TLSv1.2',
        'SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!RC4', 'SSLHonorCipherOrder On',
        f'SSLCertificateFile "{target / "server.pem"}"', f'SSLCertificateKeyFile "{target / "server.key"}"',
        'ProxyRequests Off', 'ProxyPreserveHost On', 'ProxyAddHeaders On',
        'RequestHeader unset Forwarded', 'RequestHeader unset X-Forwarded-For',
        'RequestHeader unset X-Forwarded-Proto', 'RequestHeader set X-Forwarded-Proto "https"',
        f'ProxyPass "/api/controller/" "http://127.0.0.1:{backend_port}/api/controller/" connectiontimeout=3 timeout=10',
        f'ProxyPassReverse "/api/controller/" "http://127.0.0.1:{backend_port}/api/controller/"',
        '<Location "/">', 'Require all denied', '</Location>',
        '<LocationMatch "^/api/controller/(v1/poll|v2/(poll|ack|traffic' + ('|enroll' if allow_enrollment else '') + '))$">',
        'Require ip ' + ' '.join(networks), 'LimitRequestBody 8192', '</LocationMatch>',
        '</VirtualHost>', '',
    ])
    _private_file(target / 'httpd.conf', conf)
    checked = subprocess.run([apache, '-t', '-f', str(target / 'httpd.conf')], capture_output=True)
    if checked.returncode:
        raise ValueError('Generated Apache TLS configuration failed its syntax check.')
    return {'output_dir': str(target), 'hostname': hostname, 'port': port,
            'listen_address': str(listen), 'ca_certificate': str(target / 'ca.pem'),
            'apache_config': str(target / 'httpd.conf'), 'ca_common_name': ca_name,
            'network_listener_started': False}
