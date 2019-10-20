import sanic_cookiesession as session

def init(app):
    session.setup(app)