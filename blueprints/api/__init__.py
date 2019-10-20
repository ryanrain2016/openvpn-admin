from sanic import Blueprint
from .views import UserApi, LogApi, download, CcdView, ConfView, OpenvpnView, init_log

api_bp = Blueprint('apipage', url_prefix='')

api_bp.get('/download/client-config')(download)
api_bp.add_route(CcdView.as_view(), '/api/ccd', methods=['POST', 'GET'])
api_bp.add_route(ConfView.as_view(), '/api/conf', methods=['POST', 'GET'])
api_bp.add_route(OpenvpnView.as_view(), '/api/openvpn/command', methods=['POST', 'GET'])
api_bp.add_route(init_log, '/api/init_log', methods=['GET'])

UserApi.register(api_bp, 'user')
LogApi.register(api_bp, 'log')
