from tortoise import Tortoise, run_async
from config import Config
import os
from utils import to_md5

path = os.path.dirname(__file__)
bp_path = os.path.join(path, 'blueprints')
models = ['blueprints.%s.models'%x for x in os.listdir(bp_path) if not x.startswith('__') and not x.endswith('.py')]

async def init_db():
    await Tortoise.init(
        db_url=Config.DB_URL,
        modules={'models': models}
    )
    await Tortoise.generate_schemas(safe=True)
    await init_user()

async def init_user():
    from blueprints.common.models import AdminUser
    user = AdminUser(**{
        'username': Config.ADMIN_USER,
        'password': Config.ADMIN_PASSWORD,
    })
    await user.save()

if __name__ == "__main__":
    run_async(init_db())
    # run_async(init_user())
