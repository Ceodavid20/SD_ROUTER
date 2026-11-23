"""Local administrator setup; secrets are never accepted as command arguments."""

import argparse
from getpass import getpass
from pathlib import Path
import secrets

from werkzeug.security import generate_password_hash

from services.env_storage import update_private_environment


PROJECT_ROOT = Path(__file__).resolve().parent


def configure_admin(env_path: Path, username: str, password: str) -> None:
    if not username.strip() or len(username) > 64 or any(c in username for c in "\r\n"):
        raise ValueError("The administrator username must contain 1–64 characters.")
    if len(password) < 12 or len(password) > 1024:
        raise ValueError("Use a password with 12–1024 characters.")
    password_hash = generate_password_hash(password)

    def administrator_settings(values):
        changes = {
            "SDR_ADMIN_USERNAME": username.strip(),
            "SDR_ADMIN_PASSWORD_HASH": password_hash,
        }
        if not values.get("SDR_SECRET_KEY") or len(values["SDR_SECRET_KEY"]) < 32:
            changes["SDR_SECRET_KEY"] = secrets.token_hex(32)
        if not values.get("SDR_COMPANY_NAME"):
            changes["SDR_COMPANY_NAME"] = "Network Operations"
        return changes

    update_private_environment(env_path, administrator_settings)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    administrator = commands.add_parser("configure-admin", help="Set the browser administrator locally.")
    administrator.add_argument("--username", help="Administrator username; prompted if omitted.")
    provision = commands.add_parser("provision-router", help="Create a private RouterOS polling bundle for an existing identity.")
    provision.add_argument("--router-id", required=True)
    provision.add_argument("--controller-url", help="Approved HTTPS server origin; defaults to CONTROLLER_BASE_URL.")
    provision.add_argument("--output-dir", required=True)
    provision.add_argument("--key-id", help="New key ID for initial provisioning or rotation.")
    provision.add_argument("--ca-file", help="Public controller CA certificate; never a private key.")
    revoke = commands.add_parser("revoke-router-auth", help="Revoke one key or disable a router's controller authorization.")
    revoke.add_argument("--router-id", required=True)
    revoke.add_argument("--key-id")
    traffic = commands.add_parser("prepare-traffic-client", help="Prepare a separate disabled TX collector using an existing active key; no router connection.")
    traffic.add_argument("--router-id", required=True)
    traffic.add_argument("--key-id", required=True)
    traffic.add_argument("--controller-url", help="Approved HTTPS origin; defaults to CONTROLLER_BASE_URL.")
    traffic.add_argument("--output-dir", required=True)
    tls = commands.add_parser("setup-controller-tls", help="Generate private TLS files and a device-only Apache configuration; does not start it.")
    tls.add_argument("--hostname", required=True)
    tls.add_argument("--listen-address", default="127.0.0.1")
    tls.add_argument("--port", type=int, default=18443)
    tls.add_argument("--backend-port", type=int, default=8001)
    tls.add_argument("--allow-source", action="append", required=True)
    tls.add_argument("--additional-host", action="append", default=[])
    tls.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    if args.command != "configure-admin":
        from config import load_config
        from services.json_storage import StorageError, StorageService
        from services.controller_setup_service import create_controller_tls, provision_router, revoke_router_key

        try:
            if args.command == "setup-controller-tls":
                result = create_controller_tls(
                    args.hostname, args.output_dir, listen_address=args.listen_address,
                    port=args.port, backend_port=args.backend_port,
                    allowed_sources=args.allow_source, additional_hosts=args.additional_host,
                )
                print("TLS files prepared. No network listener or firewall rule was changed.")
                print("Apache configuration:", result["apache_config"])
                print("Public CA certificate:", result["ca_certificate"])
            else:
                config = load_config()
                storage = StorageService(config["DATA_DIR"], config["OUTPUT_DIR"])
                storage.initialize()
                if args.command == "provision-router":
                    result = provision_router(
                        storage, PROJECT_ROOT / ".env", args.router_id,
                        args.controller_url or config.get("CONTROLLER_BASE_URL", ""),
                        args.output_dir, key_id=args.key_id, ca_file=args.ca_file,
                    )
                    print("Private router bundle prepared:", result["output_dir"])
                    print("Restart the device server to load the new credential reference.")
                    print("No router was contacted. No routing configuration was applied.")
                elif args.command == "prepare-traffic-client":
                    from services.traffic_setup_service import prepare_traffic_client

                    result = prepare_traffic_client(
                        storage, args.router_id, args.key_id,
                        args.controller_url or config.get("CONTROLLER_BASE_URL", ""), args.output_dir,
                    )
                    print("Private disabled traffic client prepared:", result["output_dir"])
                    print("No router, polling client, monitoring setting or TLS proxy was changed.")
                else:
                    revoke_router_key(storage, args.router_id, args.key_id)
                    print("Router controller authorization revoked.")
        except (OSError, ValueError, StorageError) as exc:
            parser.exit(1, f"Local controller setup failed: {exc}\n")
        return
    username = args.username or input("Administrator username: ").strip()
    password = getpass("New password (at least 12 characters): ")
    if password != getpass("Confirm password: "):
        parser.error("Passwords did not match.")
    try:
        configure_admin(PROJECT_ROOT / ".env", username, password)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Administrator setup failed: {exc}\n")
    print("Administrator configured. Restart the controller, then sign in.")


if __name__ == "__main__":
    main()
