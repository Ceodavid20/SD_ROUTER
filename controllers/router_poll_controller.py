"""Device-only polling endpoint; independent of browser sessions and API login."""

from flask import Blueprint, current_app, jsonify, request

from services.router_poll_service import RouterPollService
from services.router_protocol import ProtocolError, parse_poll_request
from services.routeros_poll_service import RouterOSPollService


router_poll = Blueprint("router_poll", __name__)


@router_poll.post("/api/controller/v1/poll")
def poll():
    storage = current_app.extensions["json_storage"]
    service = RouterPollService(storage, current_app.config)
    source = request.remote_addr or "unavailable"
    service.check_rate_limit(source)

    def reject(message, status, reason):
        storage.append_activity("security", "Invalid router polling request rejected.", {"reason": reason})
        return jsonify(error=message), status

    if request.mimetype != "application/json":
        return reject("Polling requests require application/json.", 415, "content_type")
    if request.query_string or request.headers.get("Content-Encoding"):
        return reject("Unsupported polling request encoding or query parameters.", 400, "request_encoding")
    raw = request.get_data(cache=False)
    try:
        payload = parse_poll_request(raw)
    except ProtocolError:
        return reject("Invalid polling request.", 400, "request_schema")
    response = service.poll(
        payload, raw, request.headers.get("X-SDR-Key-Id", ""),
        request.headers.get("X-SDR-Signature", ""), source, count_attempt=False,
    )
    return jsonify(response)


def _routeros_request(request_type):
    storage = current_app.extensions["json_storage"]
    source = request.remote_addr or "unavailable"
    RouterPollService(storage, current_app.config).check_rate_limit(source)
    if request.mimetype != "application/json":
        return jsonify(error="Router requests require application/json."), 415
    if request.query_string or request.headers.get("Content-Encoding"):
        return jsonify(error="Unsupported router request encoding or query parameters."), 400
    result = RouterOSPollService(storage, current_app.config).handle(
        request.get_data(cache=False), request.headers.get("X-SDR-Key-Id", ""),
        request.headers.get("X-SDR-Signature", ""), source,
        request_type=request_type, count_attempt=False,
    )
    return jsonify(result)


@router_poll.post("/api/controller/v2/poll")
def poll_routeros():
    return _routeros_request("poll")


@router_poll.post("/api/controller/v2/ack")
def acknowledge_routeros():
    return _routeros_request("ack")
