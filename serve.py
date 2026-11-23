"""Run the single active controller through Waitress on loopback."""

from waitress import serve

from app import create_app


def main() -> None:
    app = create_app()
    serve(
        app,
        host="127.0.0.1",
        port=8000,
        threads=4,
        max_request_body_size=64 * 1024,
        clear_untrusted_proxy_headers=True,
    )


if __name__ == "__main__":
    main()
