"""Test the complete poll locally using temporary storage and ephemeral keys.

Run from the project root: .venv/bin/python scripts/simulate_router.py
No network requests are made and operational JSON/.env files are not changed.
"""

from datetime import UTC, datetime
import json
import os
from pathlib import Path
import secrets
import sys
from tempfile import TemporaryDirectory
from uuid import uuid4


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from device_app import create_device_app
from services.router_protocol import (
    POLL_PATH, parse_utc_timestamp, sign_request, utc_text, validate_poll_response,
)


def main() -> None:
    # This is explicitly a simulated identity, never a company inventory record.
    router_id = "SIMULATED-ROUTER"
    reference = "SDR_LOCAL_SIM_" + secrets.token_hex(8).upper()
    env_name = reference + "_PRIMARY_SECRET"
    secret = secrets.token_hex(32)
    os.environ[env_name] = secret
    try:
        with TemporaryDirectory(prefix="sdr-router-simulation-") as directory:
            root = Path(directory)
            app = create_device_app({
                "TESTING": True, "SIMULATION_MODE": True, "LIVE_ROUTING_ENABLED": False,
                "DATA_DIR": root / "data", "OUTPUT_DIR": root / "output",
            })
            storage = app.extensions["json_storage"]
            storage.write_json("routers.json", [{
                "router_id": router_id, "name": "Local simulated router",
                "controller_auth_ref": reference, "controller_auth_enabled": True,
                "controller_auth_key_ids": ["PRIMARY"],
                "connection_status": "untested",
            }])
            payload = {
                "protocol_version": "1.0", "router_id": router_id,
                "request_id": str(uuid4()), "timestamp": utc_text(datetime.now(UTC)),
                "request_type": "poll",
            }
            raw = json.dumps(payload, separators=(",", ":")).encode()
            headers = {
                "X-SDR-Key-Id": "PRIMARY",
                "X-SDR-Signature": sign_request(secret, raw, "PRIMARY"),
            }
            client = app.test_client()
            response = client.post(POLL_PATH, data=raw, content_type="application/json", headers=headers)
            if response.status_code != 200:
                raise RuntimeError("Local simulated poll was rejected.")
            body = response.get_json()
            validate_poll_response(body)
            if body["router_id"] != router_id or body["request_id"] != payload["request_id"]:
                raise RuntimeError("The response identity does not match this simulated request.")
            if parse_utc_timestamp(body["expires_at"]) <= datetime.now(UTC):
                raise RuntimeError("The simulated response has expired.")
            print("LOCAL SIMULATION — temporary data; no real router contacted")
            print(json.dumps(body, indent=2))
            replay = client.post(POLL_PATH, data=raw, content_type="application/json", headers=headers)
            if replay.status_code != 409:
                raise RuntimeError("Replay protection check failed.")
            bad_raw = json.dumps({**payload, "request_id": str(uuid4())}, separators=(",", ":")).encode()
            invalid = client.post(POLL_PATH, data=bad_raw, content_type="application/json", headers={
                "X-SDR-Key-Id": "PRIMARY", "X-SDR-Signature": "0" * 64,
            })
            if invalid.status_code != 401:
                raise RuntimeError("Invalid signature check failed.")
            print("PASS: authenticated poll, response validation, identity/expiry checks, replay rejection, invalid signature rejection")
            print("No configuration was applied. Temporary simulation data has been isolated from the project data folder.")
    finally:
        os.environ.pop(env_name, None)


if __name__ == "__main__":
    main()
