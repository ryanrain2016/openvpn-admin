from jinja2 import select_autoescape, FileSystemLoader
from sanic_jinja2 import SanicJinja2
import os

jinja2 = SanicJinja2(
    enable_async = True,
    autoescape=select_autoescape(['html', 'xml']),
)

path = os.path.dirname(os.path.dirname(__file__))
bp_path = os.path.join(path, 'blueprints')
tpl_path = [os.path.join(p, 'templates') for p in os.listdir(bp_path) if not p.startswith('__')]
tpl_path.append(os.path.join(path, 'templates'))

def init(app):
    jinja2.init_app(app, loader=FileSystemLoader(tpl_path))