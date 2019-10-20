from hashlib import md5
import asyncio
import aioredis
import json

def to_str(str_or_bytes, encoding='utf-8'):
    if isinstance(str_or_bytes, bytes):
        return str_or_bytes.decode(encoding)
    return str(str_or_bytes)

def to_bytes(str_or_bytes, encoding='utf-8'):
    if isinstance(str_or_bytes, str):
        return str_or_bytes.encode(encoding)
    return str_or_bytes

def to_md5(str_or_bytes):
    s = to_bytes(str_or_bytes)
    return md5(s).hexdigest()

async def start_openvpn(app, logfile):
    p = await asyncio.create_subprocess_shell('openvpn --config conf.d/server.conf',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        )
    app.openvpn = p
    redis = await app.get_redis()
    with open(logfile, 'wb') as fd:
        while True:
            line = await p.stdout.readline()
            if not line:
                break
            fd.write(line)
            redis.publish('openvpn-admin:notify', json.dumps({
                'type': 'log',
                'data': to_str(line)
            }))
    redis.close()

def stop_openvpn(app):
    p = app.openvpn
    if p:
        p.kill()
    app.openvpn = None