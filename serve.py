"""Run the single active controller through Waitress on loopback."""

from waitress import serve

from app import create_app
from services.deployment_service import loopback_proxy_options


def main() -> None:
    app = create_app()
    serve(
        app,
        host=app.config["ADMIN_HOST"],
        port=app.config["ADMIN_PORT"],
        threads=4,
        max_request_body_size=64 * 1024,
        clear_untrusted_proxy_headers=True,
        **loopback_proxy_options(app.config["ADMIN_HOST"], app.config["ADMIN_TRUSTED_PROXY"]),
    )


if __name__ == "__main__":
    main()
