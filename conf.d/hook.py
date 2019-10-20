#!/usr/bin/env python3
from werkzeug.security import generate_password_hash,check_password_hash
from tortoise import models, fields, Tortoise
import aioredis
import os, json
import asyncio
from datetime import datetime
import sys
basedir = os.path.dirname(os.path.dirname(__file__))
sys.path.append(basedir)
from app import get_redis
from blueprints.api.models import User, Log
from extentions.db import init_db
from config import Config

DB_URL = Config.DB_URL
REDIS_URL = Config.REDIS_URL

CHANEL_NAME = 'openvpn-admin:notify'

async def publish(msg):
    if isinstance(msg, dict):
        msg = json.dumps(msg)
    redis = await get_redis()
    await redis.publish(CHANEL_NAME, msg)
    redis.close()

async def user_pass_verify():
    try:
        await init_db()
        username = os.environ.get('username')
        password = os.environ.get('password')
        user = await User.get(username=username)
        assert user.check_password(password)
    except:
        # raise
        os._exit(-1)
    else:
        os._exit(0)

async def client_connect():
    try:
        await init_db()
        username = os.environ.get('common_name')
        user = await User.get(username=username)
        ip = os.environ.get('ifconfig_pool_remote_ip')
        tip = os.environ.get('trusted_ip')
        tport = os.environ.get('trusted_port')
        user.ip = ip
        user.trusted_host = '%s:%s'%(tip, tport)
        user.online = True
        await user.save()
        log = Log(username=username, ip=ip, trusted_host=user.trusted_host)
        await log.save()
        await publish({
            'type': 'update',
            'msg': {
                'title': '客户端%s连接，ip为%s'%(username, ip)
            }
        })
    except:
        # raise
        os._exit(-1)
    else:
        os._exit(0)

async def client_disconnect():
    try:
        await init_db()
        username = os.environ.get('common_name')
        user = await User.get(username=username)
        user.online = False
        user.ip = ''
        await user.save()
        bytes_sent = os.environ.get('bytes_sent')
        bytes_received = os.environ.get('bytes_received')
        log = await Log.filter(username=username).filter(offline_time=None).order_by('-id').first()
        log.bytes_received = bytes_received
        log.bytes_sent = bytes_sent
        log.offline_time = datetime.now()
        await log.save()
        await publish({
            'type': 'update',
            'msg': {
                'title': '客户端%s断开连接。'%(username)
            }
        })
    except:
        # raise
        os._exit(-1)
    else:
        os._exit(0)

def run(coro):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(coro)

if __name__ == "__main__":
    script_type = os.environ.get('script_type')
    print(script_type)
    coro = globals().get(script_type.replace('-', '_'))
    run(coro())
