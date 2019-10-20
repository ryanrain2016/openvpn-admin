from sanic import Blueprint, views
from .views import LoginView, HomeView, LogoutView, GetToken, GetUserInfo
from config import Config

common_bp = Blueprint('common', url_prefix=Config.ROOT_URL)

common_bp.add_route(LoginView.as_view(), '/login', name='login')
common_bp.add_route(HomeView.as_view(), '/', name='adminhome')
common_bp.add_route(LogoutView.as_view(), '/auth/logout', name='logout')
common_bp.add_route(GetToken.as_view(), '/auth/login', name='token')
common_bp.add_route(GetUserInfo.as_view(), '/api/user/info', name='userinfo')