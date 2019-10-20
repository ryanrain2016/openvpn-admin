from sanic import Sanic
from extentions import init_app
from blueprints import common_bp, api_bp, ws_bp
import aioredis
import config
import asyncio, json
from utils import to_str, start_openvpn

app = Sanic(__name__, load_env=False)
app.config.from_object(config.Config)

async def get_redis():
    return await aioredis.create_redis(config.Config.REDIS_URL)

@app.listener('before_server_start')
async def server_init(app, loop):
    """init extensions"""
    await init_app(app)
    app.redis = await aioredis.create_redis_pool(config.Config.REDIS_URL,
        minsize=config.Config.REDIS_POOL_MINSIZE,
        maxsize=config.Config.REDIS_POOL_MAXSIZE
        )
    app.get_redis = get_redis
    asyncio.ensure_future(start_openvpn(app, config.Config.OPENVPN_LOGFILE))

@app.listener('after_server_stop')
async def server_destory(app, loop):
    app.redis.close()
    app.openvpn.terminate()

app.blueprint(common_bp)
app.blueprint(api_bp)
app.blueprint(ws_bp)

app.static('/static', './static', name='static')

if __name__ == '__main__':
    app.run(debug=config.DEBUG, port=12345, host='0.0.0.0')

