"""Run the loopback device backend, optionally behind one approved TLS proxy."""

from ipaddress import ip_address

from waitress import serve

from device_app import create_device_app


def main() -> None:
    app = create_device_app()
    host = app.config["CONTROLLER_HOST"]
    try:
        local = host == "localhost" or ip_address(host).is_loopback
    except ValueError:
        local = False
    if not local:
        raise ValueError(
            "Bind the device backend to loopback. Use an approved HTTPS reverse proxy for router access."
        )
    proxy = app.config.get("CONTROLLER_TRUSTED_PROXY", "")
    proxy_options = {}
    if proxy:
        try:
            trusted = ip_address(proxy)
        except ValueError as exc:
            raise ValueError("CONTROLLER_TRUSTED_PROXY must be one explicit loopback IP.") from exc
        if not trusted.is_loopback:
            raise ValueError("The TLS proxy must connect through loopback.")
        proxy_options = {
            "trusted_proxy": str(trusted), "trusted_proxy_count": 1,
            "trusted_proxy_headers": {"x-forwarded-for", "x-forwarded-proto"},
        }
    serve(
        app, host=host, port=app.config["CONTROLLER_PORT"], threads=4,
        max_request_body_size=8192, clear_untrusted_proxy_headers=True,
        **proxy_options,
    )


if __name__ == "__main__":
    main()
