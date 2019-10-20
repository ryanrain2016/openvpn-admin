from tortoise import Tortoise
from config import Config
import os

path = os.path.dirname(os.path.dirname(__file__))
bp_path = os.path.join(path, 'blueprints')
models = ['blueprints.%s.models'%x for x in os.listdir(bp_path) if not x.startswith('__') and not x.endswith('.py')]

async def init_db():
    await Tortoise.init(
        db_url=Config.DB_URL,
        modules={'models': models}
    )