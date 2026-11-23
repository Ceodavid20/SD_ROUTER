"""Separate device-only TX telemetry endpoint; no browser session or commands."""

from flask import Blueprint, current_app, jsonify, request

from services.traffic_service import TrafficService


router_traffic = Blueprint("router_traffic", __name__)


@router_traffic.post("/api/controller/v2/traffic")
def traffic():
    service = TrafficService(current_app.extensions["json_storage"], current_app.config)
    source = request.remote_addr or "unavailable"
    service.check_rate_limit(source)
    if request.mimetype != "application/json":
        return jsonify(error="Traffic requests require application/json."), 415
    if request.query_string or request.headers.get("Content-Encoding"):
        return jsonify(error="Unsupported traffic request encoding or query parameters."), 400
    return jsonify(service.handle(
        request.get_data(cache=False), request.headers.get("X-SDR-Key-Id", ""),
        request.headers.get("X-SDR-Signature", ""), source, count_attempt=False,
    ))
