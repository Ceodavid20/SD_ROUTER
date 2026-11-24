"""Local administrator setup; secrets are never accepted as command arguments."""

import argparse
from getpass import GetPassWarning, getpass
from pathlib import Path
import secrets
import warnings

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
    api_setup = commands.add_parser("configure-router-api", help="Privately save an existing router's API login; no router connection or transport changes.")
    api_setup.add_argument("--router-id", required=True)
    register = commands.add_parser("register-monitoring-router", help="Register an existing carrier router locally; no device commands or automatic monitoring.")
    register.add_argument("--router-id", required=True)
    register.add_argument("--name", required=True)
    register.add_argument("--management-ip", required=True)
    register.add_argument("--outbound-interface", required=True)
    register.add_argument("--management-interface", required=True)
    register.add_argument("--carrier", required=True)
    register.add_argument("--chr-lab", action="store_true")
    register.add_argument("--bind-source", action="store_true", help="Optionally restrict TX ingestion to this fixed management IP; omit for NAT/dynamic sources.")
    register.add_argument("--api-port", type=int, default=8729)
    enrollment = commands.add_parser("create-enrollment-token", help="Authorize one trusted router bootstrap; token is written privately and never printed.")
    enrollment.add_argument("--output-dir", required=True)
    enrollment.add_argument("--ca-file", required=True, help="Trusted public controller CA supplied through the bootstrap channel.")
    enrollment.add_argument("--interface", required=True)
    enrollment.add_argument("--router-id")
    enrollment.add_argument("--name", default="")
    enrollment.add_argument("--carrier", default="")
    enrollment.add_argument("--management-ip", default="")
    enrollment.add_argument("--management-interface", default="")
    enrollment.add_argument("--chr-lab", action="store_true")
    enrollment.add_argument("--enable-monitoring", action="store_true")
    enrollment.add_argument("--bind-source", action="store_true")
    enrollment.add_argument("--replace-existing", action="store_true")
    enrollment.add_argument("--interval-seconds", type=int)
    enrollment.add_argument("--ttl-seconds", type=int, default=900)
    revoke_enrollment = commands.add_parser("revoke-enrollment-token", help="Revoke an unused enrollment authorization.")
    revoke_enrollment.add_argument("--enrollment-id", required=True)
    provision = commands.add_parser("provision-router", help="Create a private RouterOS polling bundle for an existing identity.")
    provision.add_argument("--router-id", required=True)
    provision.add_argument("--controller-url", help="Approved HTTPS server origin; defaults to CONTROLLER_BASE_URL.")
    provision.add_argument("--output-dir", required=True)
    provision.add_argument("--key-id", help="New key ID for initial provisioning or rotation.")
    provision.add_argument("--ca-file", help="Public controller CA certificate; never a private key.")
    revoke = commands.add_parser("revoke-router-auth", help="Revoke one key or disable a router's controller authorization.")
    revoke.add_argument("--router-id", required=True)
    revoke.add_argument("--key-id")
    optimizer = commands.add_parser("prepare-optimization-client", help="Prepare a disabled advisory pull/result client; no router connection.")
    optimizer.add_argument("--router-id", required=True)
    optimizer.add_argument("--key-id", required=True)
    optimizer.add_argument("--controller-url", help="Approved HTTPS origin; defaults to CONTROLLER_BASE_URL.")
    optimizer.add_argument("--output-dir", required=True)
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
    tls.add_argument("--allow-enrollment", action="store_true")
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
                    allow_enrollment=args.allow_enrollment,
                )
                print("TLS files prepared. No network listener or firewall rule was changed.")
                print("Apache configuration:", result["apache_config"])
                print("Public CA certificate:", result["ca_certificate"])
            else:
                config = load_config()
                from services.deployment_service import validate_deployment, profile_path
                validate_deployment(config)
                if getattr(args, "output_dir", None):
                    profile_path(config, args.output_dir)
                if getattr(args, "ca_file", None):
                    profile_path(config, args.ca_file)
                storage = StorageService(config["DATA_DIR"], config["OUTPUT_DIR"])
                storage.initialize()
                if args.command == "configure-router-api":
                    from services.api_credentials_service import configure_api_credentials, registered_api_target

                    registered_api_target(storage, args.router_id)
                    with warnings.catch_warnings():
                        warnings.simplefilter("error", GetPassWarning)
                        try:
                            username = getpass("Router API username (hidden): ")
                            password = getpass("Router API password (hidden): ")
                        except GetPassWarning:
                            raise ValueError("Run credential setup in an interactive terminal that supports hidden input.") from None
                    configure_api_credentials(storage, config, args.router_id, username, password)
                    print("API credentials saved privately for the existing router.")
                    print("Reload Routers and run the optional diagnostic. No server restart is needed.")
                    print("No router was contacted. API port, TLS policy, polling and TX settings were preserved.")
                elif args.command == "create-enrollment-token":
                    from services.enrollment_service import create_enrollment_grant

                    result = create_enrollment_grant(
                        storage, config, args.output_dir, args.ca_file,
                        interface=args.interface, router_id=args.router_id, name=args.name,
                        carrier=args.carrier, management_ip=args.management_ip,
                        management_interface=args.management_interface, chr_lab=args.chr_lab,
                        enable_monitoring=args.enable_monitoring, bind_source=args.bind_source,
                        replace_existing=args.replace_existing, interval_seconds=args.interval_seconds,
                        ttl_seconds=args.ttl_seconds,
                    )
                    print("Private, single-use bootstrap bundle:", result["output_dir"])
                    print("Authorization expires:", result["expires_at"])
                    print("Deliver its bootstrap and public CA through your trusted initial setup channel.")
                    print("No router was contacted. The token and credentials were not printed.")
                elif args.command == "revoke-enrollment-token":
                    import re
                    if not re.fullmatch(r"[0-9a-f]{32}", args.enrollment_id):
                        raise ValueError("Enter a valid enrollment authorization ID.")
                    def revoke_grant(state):
                        grant = state["grants"].get(args.enrollment_id)
                        if grant is None or grant["used_at"] is not None:
                            raise ValueError("The unused enrollment authorization is unavailable.")
                        del state["grants"][args.enrollment_id]
                        return state
                    storage.update_json("router_enrollment.json", revoke_grant)
                    storage.append_activity("enrollment", "Unused enrollment authorization revoked.")
                    print("Enrollment authorization revoked; registered routers were preserved.")
                elif args.command == "register-monitoring-router":
                    from services.router_service import RouterService

                    RouterService(storage, config).register_monitoring_router(
                        args.router_id, args.name, args.management_ip, args.outbound_interface,
                        args.management_interface, args.carrier, chr_lab=args.chr_lab,
                        bind_source=args.bind_source, api_port=args.api_port,
                    )
                    print("Existing router registered locally; capacities remain operator-configured.")
                    print("No router was contacted. Monitoring and controller keys were not automatically enabled.")
                elif args.command == "provision-router":
                    result = provision_router(
                        storage, config["CONTROLLER_CREDENTIALS_ENV_FILE"], args.router_id,
                        args.controller_url or config.get("CONTROLLER_BASE_URL", ""),
                        args.output_dir, key_id=args.key_id, ca_file=args.ca_file,
                    )
                    print("Private router bundle prepared:", result["output_dir"])
                    print("Restart the device server to load the new credential reference.")
                    print("No router was contacted. No routing configuration was applied.")
                elif args.command == "prepare-optimization-client":
                    from services.traffic_setup_service import prepare_optimization_client
                    result = prepare_optimization_client(storage, args.router_id, args.key_id,
                        args.controller_url or config.get("CONTROLLER_BASE_URL", ""), args.output_dir, config=config)
                    print("Private disabled advisory client prepared:", result["output_dir"])
                    print("No router was contacted. Routing execution remains disabled.")
                elif args.command == "prepare-traffic-client":
                    from services.traffic_setup_service import prepare_traffic_client

                    result = prepare_traffic_client(
                        storage, args.router_id, args.key_id,
                        args.controller_url or config.get("CONTROLLER_BASE_URL", ""), args.output_dir,
                        config=config,
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
        from config import load_config
        from services.deployment_service import validate_deployment
        config = load_config()
        validate_deployment(config, setup=True)
        configure_admin(config["CONFIG_ENV_FILE"], username, password)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Administrator setup failed: {exc}\n")
    print("Administrator configured. Restart the controller, then sign in.")


if __name__ == "__main__":
    main()
