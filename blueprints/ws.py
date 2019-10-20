import asyncio
import json
import os
import re
from inspect import isawaitable

from sanic import Blueprint

from config import Config
from framework.ws import RedisChannelWebsocket
from utils import to_str, to_bytes

ws_bp = Blueprint('ws', url_prefix='/ws')

class WebsocketHandler(RedisChannelWebsocket):
    async def pre_send(self, msg):
        return to_str(msg)


class WsSendMixin:
    def send(self, data):
        if isinstance(data, (dict, list)):
            data = json.dumps(data)
        else:
            data = to_str(data)
        asyncio.ensure_future(self.ws.send(data))


class CommandProtocol(asyncio.Protocol, WsSendMixin):
    def __init__(self, ws):
        self.ws = ws
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        self.send({
            'type': 'cmd_log',
            'data': ['openvpn manage连接成功。']
        })

    def data_received(self, data):
        data = to_str(data)
        self.send({
            'type': 'cmd_log',
            'data': [data]
        })

    def connection_lost(self, exc):
        self.send({
            'type': 'cmd_log',
            'data': ['openvpn manage断开连接。']
        })

def get_management_addr():
    conf_file = os.path.join(Config.BASEDIR, 'conf.d', 'server.conf')
    with open(conf_file) as fd:
        content = fd.read()
    # content = ' '.join(content.splitlines())
    m = re.search(r'management\s+(?P<ip>\S+)\s+(?P<port>\S+)', content, re.M)
    ip = m.group('ip')
    if ip == '0.0.0.0':
        ip = '127.0.0.1'
    port = int(m.group('port'))
    return ip, port

class CommandHandler(WsSendMixin):
    def __init__(self, ws):
        self.ws = ws
        self.manage_transport = None

    async def __call__(self, msg):
        msg = json.loads(to_str(msg))
        cmd = msg.get('cmd')
        attr = getattr(self, cmd, lambda *x:x)
        ret = attr(msg)
        if isawaitable(ret):
            await ret

    async def connect(self, msg):
        if self.manage_transport and not self.manage_transport.is_closing():
            self.send({
                'type': 'cmd_log',
                'data': ['openvpn管理服务已连接']
            })
            return
        try:
            ip, host = get_management_addr()
        except:
            self.send({
                'type': 'cmd_log',
                'data': ['openvpn管理服务未开通管理端口。']
            })
            return
        loop = asyncio.get_event_loop()
        try:
            self.manage_transport, _ = await loop.create_connection(lambda: CommandProtocol(self.ws), ip, host)
        except asyncio.TimeoutError:
            self.send({
                'type': 'cmd_log',
                'data': ['openvpn管理服务连接超时。']
            })
        except ConnectionRefusedError:
            self.send({
                'type': 'cmd_log',
                'data': ['openvpn管理服务连接被拒绝。']
            })
        except ConnectionAbortedError:
            self.send({
                'type': 'cmd_log',
                'data': ['openvpn管理服务连接终止。']
            })
        except:
            self.send({
                'type': 'cmd_log',
                'data': ['openvpn管理服务连接失败，未知错误。']
            })

    async def disconnect(self, msg=None):
        if self.manage_transport and not self.manage_transport.is_closing():
            self.manage_transport.close()

    def write_command(self, command):
        if self.manage_transport and not self.manage_transport.is_closing():
            self.manage_transport.write(to_bytes(command))
        else:
            self.send({
                'type': 'cmd_log',
                'data': ['openvpn管理服务未连接。']
            })

    async def command(self, msg):
        command = msg.get('data')
        command = command.strip() + '\r\n'
        self.write_command(command)

@ws_bp.websocket('/notify')
async def notify(request, ws):
    try:
        handler = CommandHandler(ws)
        coro = WebsocketHandler(request, ws, handler, channel_names='openvpn-admin:notify')()
        coro = asyncio.shield(coro)
        await coro
    except Exception as e:
        print(e)
    finally:
        await handler.disconnect()
