"""Device-only enrollment boundary. Bootstrap tokens require verified HTTPS."""

from flask import Blueprint, current_app, jsonify, request

from services.enrollment_service import EnrollmentService


router_enrollment = Blueprint("router_enrollment", __name__)


@router_enrollment.post("/api/controller/v2/enroll")
def enroll():
    service = EnrollmentService(current_app.extensions["json_storage"], current_app.config)
    source = request.remote_addr or "unavailable"
    service.check_rate_limit(source)
    if not request.is_secure:
        return jsonify(error="Verified HTTPS is required for enrollment."), 403
    if request.mimetype != "application/json":
        return jsonify(error="Enrollment requires application/json."), 415
    if request.query_string or request.headers.get("Content-Encoding"):
        return jsonify(error="Unsupported enrollment encoding or query parameters."), 400
    return jsonify(service.enroll(request.get_data(cache=False), request.headers.get("Authorization", ""),
                                  source, count_attempt=False))
