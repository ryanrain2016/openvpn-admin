from sanic import views, response
from sanic.request import Request
from extentions import jinja2
from .models import AdminUser
from tortoise.exceptions import DoesNotExist
import jwt
import time
from framework.api import verify_token
from config import Config
from utils import to_str, to_bytes
from hashlib import sha1
import hmac
from urllib.parse import urlencode, quote


class LoginView(views.HTTPMethodView):
    async def get(self, request):
        if request['session'].get('user'):
            return response.redirect(request.app.url_for('common.adminhome'))
        return await jinja2.render_async('login.html', request)

    async def post(self, request):
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            user:AdminUser = await AdminUser.get(username=username)
            if not user or user.check_password(password):
                request['session']['user'] = username
                return response.redirect(request.app.url_for('common.adminhome'))
        except DoesNotExist as e:
            return await jinja2.render_async('login.html', request)
        return await jinja2.render_async('login.html', request)

class HomeView(views.HTTPMethodView):
    async def get(self, request:Request):
        username = request['session'].get('user')
        if not username:
            return response.redirect(request.app.url_for('common.login'))
        user = await AdminUser.get(username=username)
        return await jinja2.render_async('index.html', request, user=user)


class LogoutView(views.HTTPMethodView):
    async def post(self, request:Request):
       request['session']['user'] = None
       del request['session']['user']
       return response.redirect(request.app.url_for('common.adminhome'))

class GetToken(views.HTTPMethodView):
    async def post(self, request:Request):
        params =  request.form or request.json
        username = params.get('username')
        password = params.get('password')
        try:
            user:AdminUser = await AdminUser.get(username=username)
            if user.check_password(password):
                payload = {
                    'exp': int(time.time()) + 86400 * 7,
                    'user_id': user.id,
                    'username': user.username,
                    'avatar': user.avatar,
                }
                secret = request.app.config['TOKEN_SECRET_KEY']
                token = jwt.encode(payload, secret, algorithm='HS256').decode()
                user_dict = user.to_dict()
                del user_dict['_password']
                user_dict['token'] = token
                return response.json({
                    'code': 200,
                    'message': '',
                    'result': user_dict
                })
        except DoesNotExist as e:
            pass
        return response.json({
            'code': 401,
            'message': '用户名或者密码不正确',
            'result': None
        }, status=401)

    async def get(self, request):
        auth = request.headers.get('Authorization')
        secret = request.app.config['TOKEN_SECRET_KEY']
        if not auth:
            return response.text('', status=401)
        token = auth.split().pop()
        ok, payload = verify_token(token, secret)
        if ok:
            payload['exp'] = payload['exp'] + 84600*3
            token = jwt.encode(payload, secret, algorithm='HS256').decode()
            return response.json({'token':token})
        return response.text('', status=401)

class GetUserInfo(views.HTTPMethodView):
    async def get(self, request):
        auth = request.args.get('token')
        if not auth:
            auth = request.headers.get('Authorization', None)
        if not auth:
            return response.text('', status=401)
        secret = request.app.config['TOKEN_SECRET_KEY']
        token = auth.split().pop()
        ok, payload = verify_token(token, secret)
        if ok:
            try:
                user:AdminUser = await AdminUser.get(pk=payload.get('user_id'))
                # result = {
                #     'id': user.id,
                #     'name': user.name,
                #     'username': user.username,
                #     'password': '',
                #     'avatar': user.avatar,
                #     'status': user.status,
                #     'telephone': user.telephone,
                #     'lastLoginIp': user.lastLoginIp,
                #     'lastLoginTime': user.lastLoginTime,
                #     'creatorId': user.creatorId,
                #     'createTime': user.createTime,
                #     'merchantCode': 'TLif2btpzg079h15bk',
                #     'deleted': user.deleted,
                #     'roleId': user.roleId,
                #     'role': {
                #         'permissions': [
                #             {}
                #         ]
                #     }
                # }
                user_dict = user.to_dict()
                del user_dict['_password']
                user_dict.update(role = {
                    'permissions': [
                        {}
                    ]
                })
                return response.json({
                    'code': 200,
                    'result': user_dict,
                    'message': ''
                })
            except DoesNotExist:
                pass
        return response.text('', status=401)

