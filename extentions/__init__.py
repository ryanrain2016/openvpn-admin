from . import jinja
from . import session
from . import db
from .jinja import jinja2
from .certs_ex import init_cert

async def init_app(app):
    await db.init_db()
    session.init(app)
    jinja.init(app)
    init_cert(app)