import asyncio
import io
import os
import zipfile

import aiofiles
from aiofiles.os import stat
from sanic import response, views
from sanic.exceptions import HeaderNotFound
from sanic.handlers import ContentRangeHandler
from tortoise.exceptions import DoesNotExist
from tortoise.transactions import in_transaction

from config import Config
from framework.api import (BaseApi, DeleteMixin, GetListMixin, GetMixin,
                           PatchMixin, PostMixin, PutMixin, ReadMixin,
                           WriteMixin, Pagination)
from utils import start_openvpn, stop_openvpn

from . import models


async def static(request, filename):
    stats = await stat(filename)
    _range = None
    headers = {}
    headers['Accept-Ranges'] = 'bytes'
    headers['Content-Length'] = str(stats.st_size)
    try:
        _range = ContentRangeHandler(request, stats)
    except HeaderNotFound:
        headers['Content-Disposition'] = 'inline; filename=%s' % (filename.rsplit(os.path.sep, 1).pop(-1))
    else:
        del headers['Content-Length']
        for key, value in _range.headers.items():
            headers[key] = value
    resp = await response.file_stream(filename, headers=headers, _range=_range)
    if _range:
        resp.status=206
    return resp

class UserApi(BaseApi, ReadMixin, WriteMixin, DeleteMixin):
    model = models.User
    pagination_class= None

    @classmethod
    def verify_request(cls, request):
        return request['session'].get('user')

class LogPagination(Pagination):
    page_size = 15

class LogApi(BaseApi, ReadMixin):
    model = models.Log
    pagination_class = LogPagination

    @classmethod
    def verify_request(cls, request):
        return request['session'].get('user')

    @classmethod
    def get_queryset(cls, request):
        qs = cls.model.all()
        order_by = request.args.get('order_by', None)
        if order_by:
            qs = qs.order_by(order_by)
        username = request.args.get('username', None)
        if username:
            qs = qs.filter(username=username)
        return qs

async def download(request):
    if request['session'].get('user'):
        conf_dir = os.path.join(Config.BASEDIR, 'conf.d')
        zip_file = io.BytesIO()
        with zipfile.ZipFile(zip_file, 'w') as fd:
            fd.write(os.path.join(conf_dir, 'ca.crt'), 'ca.crt')
            fd.write(os.path.join(conf_dir, 'ta.key'), 'ta.key')
            with open(os.path.join(conf_dir, 'client.conf')) as f:
                content = f.read()
            fd.writestr('client.conf', content%(Config.SERVER_IP, Config.SERVER_PORT))
        content = zip_file.getvalue()
        return response.raw(content, content_type='application/x-zip-compressed')
    else:
        return response.text('', status=404)



class CcdView(views.HTTPMethodView):
    async def get(self, request):
        name = request.args.get('username')
        if request['session'].get('user'):
            filename = os.path.join(Config.BASEDIR, 'conf.d', 'ccd', name)
            content = ''
            if os.path.exists(filename):
                with open(filename, 'r', encoding='utf-8') as fd:
                    content = fd.read()
            return response.text(content)
        else:
            return response.text('', status=404)

    async def post(self, request):
        name = request.args.get('username')
        if request['session'].get('user'):
            filename = os.path.join(Config.BASEDIR, 'conf.d', 'ccd', name)
            content = request.json.get('content')
            with open(filename, 'w', encoding='utf-8') as fd:
                fd.write(content)
            return response.json({'code': 0, 'msg': '保存成功'})
        else:
            return response.text('', status=404)

class ConfView(views.HTTPMethodView):
    async def get(self, request):
        if request['session'].get('user'):
            filename = os.path.join(Config.BASEDIR, 'conf.d', 'server.conf')
            content = ''
            if os.path.exists(filename):
                with open(filename, 'r', encoding='utf-8') as fd:
                    content = fd.read()
            return response.text(content)
        else:
            return response.text('', status=404)

    async def post(self, request):
        if request['session'].get('user'):
            filename = os.path.join(Config.BASEDIR, 'conf.d', 'server.conf')
            content = request.json.get('content')
            with open(filename, 'w', encoding='utf-8') as fd:
                fd.write(content)
            return response.json({'code': 0, 'msg': '保存成功'})
        else:
            return response.text('', status=404)

class OpenvpnView(views.HTTPMethodView):
    async def post(self, request):
        command = request.json.get('command')
        if command == 'start':
            asyncio.ensure_future(start_openvpn(request.app, Config.OPENVPN_LOGFILE))
        elif command == 'stop':
            stop_openvpn(request.app)
        elif command == 'restart':
            stop_openvpn(request.app)
            asyncio.ensure_future(start_openvpn(request.app, Config.OPENVPN_LOGFILE))
        else:
            return response.text('', status=404)
        return response.json({'code': 0, 'msg': '操作成功'})

async def init_log(request):
    if request['session'].get('user'):
        filename = os.path.join(Config.BASEDIR, Config.OPENVPN_LOGFILE)
        with open(filename) as fd:
            lines = fd.readlines()
        return response.json({
            'code': 0,
            'data': lines[-200:]
        })
    return response.text('', status=404)
