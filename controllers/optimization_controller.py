"""Device-only advisory pull and separate application-result reporting."""
from flask import Blueprint,current_app,jsonify,request
from services.optimization_pull_service import OptimizationPullService

router_optimization=Blueprint('router_optimization',__name__)

def exchange(kind):
    service=OptimizationPullService(current_app.extensions['json_storage'],current_app.config)
    source=request.remote_addr or 'unavailable'
    service.check_rate_limit(source)
    if request.mimetype!='application/json':
        return jsonify(error='Optimization requests require application/json.'),415
    if request.query_string or request.headers.get('Content-Encoding'):
        return jsonify(error='Unsupported query or encoding.'),400
    return jsonify(service.handle(request.get_data(cache=False),request.headers.get('X-SDR-Key-Id',''),
        request.headers.get('X-SDR-Signature',''),source,kind,count_attempt=False))

@router_optimization.post('/api/controller/v2/optimization')
def pull():
    return exchange('optimization')

@router_optimization.post('/api/controller/v2/optimization/result')
def result():
    return exchange('optimization_result')
