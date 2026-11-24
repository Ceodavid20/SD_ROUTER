"""Prepare an optional disabled traffic client locally; never contact a router."""

import os
import re
from pathlib import Path

from services.controller_setup_service import (
    PROJECT_ROOT, _https_origin, _new_private_directory, _private_file,
    _routeros_string, render_routeros_script,
)
from services.controller_status_service import _authorization_enabled
from services.json_storage import StorageService
from services.router_protocol import ROUTER_ID
from services.traffic_protocol import validate_interface
from services.traffic_service import monitored_interfaces
from services.api_credentials_service import controller_secret


def render_traffic_script(router_id: str, key_id: str, secret: str, base_url: str, interface: str, *, fetch_timeout_seconds=10) -> str:
    if isinstance(interface, list):
        monitored_interfaces({"interface_name": interface[0] if interface else None, "monitoring_interfaces": interface})
        scripts = [render_traffic_script(router_id, key_id, secret, base_url, name, fetch_timeout_seconds=fetch_timeout_seconds) for name in interface]
        # One explicit opt-in controls the whole authorized list. Each channel
        # keeps its own counter and fresh nonce; failures do not fabricate rates.
        header = ":local sdrTrafficEnabled false;\n:if ($sdrTrafficEnabled != true) do={ :put \"SDR outbound collection is disabled\"; :return; };\n"
        return header + "\n".join(script.replace(":local sdrTrafficEnabled false;", ":local sdrTrafficEnabled true;", 1) for script in scripts)
    validate_interface(interface)
    # Reuse the validated settings and exact HMAC implementation of the
    # existing client; its poll and ACK source is never edited or installed.
    poll_script = render_routeros_script(router_id, key_id, secret, base_url, fetch_timeout_seconds=fetch_timeout_seconds)
    helper = poll_script.split("    # SDR_HMAC_BEGIN\n", 1)[1].split("    # SDR_HMAC_END", 1)[0]
    template = (PROJECT_ROOT / "scripts/routeros/controller_traffic_v2.rsc").read_text()
    values = {
        "__ROUTER_ID__": router_id, "__KEY_ID__": key_id, "__SHARED_SECRET__": secret,
        "__CONTROLLER_BASE_URL__": _https_origin(base_url), "__INTERFACE__": interface,
        "__FETCH_TIMEOUT_SECONDS__": str(fetch_timeout_seconds),
    }
    # A single substitution pass prevents interface text becoming a template
    # directive. Only the inserted HMAC helper is code; settings are escaped.
    replacements = {key: _routeros_string(value) for key, value in values.items()}
    replacements["__HMAC_HELPER__"] = helper.rstrip()
    return (PROJECT_ROOT / 'scripts/routeros/controller_preflight.rsc').read_text() + '\n' + re.sub(r"__[A-Z_]+__", lambda match: replacements[match.group()], template)


def prepare_traffic_client(
    storage: StorageService, router_id: str, key_id: str, base_url: str, output_dir: str | Path, config=None,
) -> dict:
    if not isinstance(router_id, str) or not ROUTER_ID.fullmatch(router_id):
        raise ValueError("Invalid router identity.")
    router = next((item for item in storage.read_json("routers.json") if item["router_id"] == router_id), None)
    if router is None or not _authorization_enabled(router):
        raise ValueError("Provision controller authentication for this registered router first.")
    if key_id not in router["controller_auth_key_ids"]:
        raise ValueError("Select an active controller key ID.")
    if config is None:
        from config import load_config
        config = load_config()
    secret = controller_secret(router, key_id, config)
    script = render_traffic_script(router_id, key_id, secret, base_url, monitored_interfaces(router) if "monitoring_interfaces" in router else router.get("interface_name"), fetch_timeout_seconds=config.get("ROUTER_FETCH_TIMEOUT_SECONDS", 10))
    target = _new_private_directory(output_dir)
    _private_file(target / "controller-traffic.rsc", script)
    _private_file(target / "README.txt", (
        "PRIVATE DISABLED OUTBOUND COLLECTOR\n"
        "The script contains an existing router authentication key. Never print or share its source.\n"
        "It is disabled by default and has not been validated on the target RouterOS device.\n"
        "No router was contacted and no registry, environment, polling client or TLS proxy was changed.\n"
        "Obtain approval before target-device validation, installation, scheduling or proxy changes.\n"
        "Enable the configured interface in the controller's Traffic monitoring page only when ready.\n"
        "After approval and review, explicitly set sdrTrafficEnabled true in the private script.\n"
        "Use the existing verified HTTPS origin and trusted public CA. Never disable certificate checks.\n"
        "It reads only tx-byte for the configured TX interfaces and signs each request independently; it installs no scheduler.\n"
    ))
    return {"output_dir": str(target), "router_id": router_id, "enabled": False}


def prepare_optimization_client(storage,router_id,key_id,base_url,output_dir,config=None):
    """Prepare a disabled read/report-only native client, without router I/O."""
    if not isinstance(router_id,str) or not ROUTER_ID.fullmatch(router_id):
        raise ValueError('Invalid router identity.')
    router=next((r for r in storage.read_json('routers.json') if r['router_id']==router_id),None)
    if router is None or not _authorization_enabled(router) or key_id not in router['controller_auth_key_ids']:
        raise ValueError('Select an authorized router and active key.')
    if config is None:
        from config import load_config
        config=load_config()
    secret=controller_secret(router,key_id,config)
    poll=render_routeros_script(router_id,key_id,secret,base_url,fetch_timeout_seconds=config.get("ROUTER_FETCH_TIMEOUT_SECONDS",10))
    helper=poll.split('    # SDR_HMAC_BEGIN\n',1)[1].split('    # SDR_HMAC_END',1)[0]
    template=(PROJECT_ROOT/'scripts/routeros/controller_optimization_v2.rsc').read_text()
    values={'__ROUTER_ID__':router_id,'__KEY_ID__':key_id,'__SHARED_SECRET__':secret,
            '__CONTROLLER_BASE_URL__':_https_origin(base_url), '__FETCH_TIMEOUT_SECONDS__':str(config.get("ROUTER_FETCH_TIMEOUT_SECONDS",10))}
    replacements={key:_routeros_string(value) for key,value in values.items()}
    replacements['__HMAC_HELPER__']=helper.rstrip()
    script=(PROJECT_ROOT / 'scripts/routeros/controller_preflight.rsc').read_text() + '\n' + re.sub(r'__[A-Z_]+__',lambda match:replacements[match.group()],template)
    target=_new_private_directory(output_dir)
    _private_file(target/'controller-optimization.rsc',script)
    _private_file(target/'README.txt',
        'PRIVATE DISABLED ADVISORY CLIENT\nContains a router key: never print or share its source.\n'
        'No router was contacted. Review and authorize installation/scheduling separately.\n'
        'After approval, explicitly enable sdrOptimizationEnabled. It validates HTTPS, scope, validity and versions; '
        'reports not_applied; contains no routing executor. It is not yet device-validated.\n'
        'Permit the two optimization paths through the existing restricted TLS proxy. '
        'Keep existing poll/ACK/traffic clients and verified CA.\n')
    return {'output_dir':str(target),'router_id':router_id,'enabled':False}
