import os

DEBUG=False
class CommonConfig:
    SESSION_COOKIE_SECRET_KEY = '38509jfog50950R#$TR54twerR#$Rfdsf2095ojdofjg5434085464jgreg'
    SESSION_COOKIE_SECURE = False
    # TOKEN_SECRET_KEY = 'dggtrggrtgrttyhg'
    BASEDIR = os.path.dirname(__file__)

    REDIS_POOL_MINSIZE = 5
    REDIS_POOL_MAXSIZE = 20
    CA_CN = 'openvpn.org'              # openvpn证书的ca
    SERVER_CN = 'server.openvpn.org'    # openvpn服务端ca
    ORGANIZATION = 'openvpn.org'        # openvpn证书组织

    OPENVPN_LOGFILE = 'logs/openvpn.log' # openvpn 的日志
    SERVER_IP = ''       # openvpn 监听的IP
    SERVER_PORT = 1194    # openvpn 监听的端口，若要修改需同步修改 conf.d/server.conf 文件

    ADMIN_USER = 'xxx'
    ADMIN_PASSWORD = 'dfsdfdsf'

class DEV(CommonConfig):
    DB_URL = 'sqlite://db.sqlite3'    # 支持sqlite和mysql
    ROOT_URL = '/'
    REDIS_URL = 'redis://127.0.0.1'

class PRED(CommonConfig):
    DB_URL = 'sqlite://db.sqlite3'
    ROOT_URL = '/'
    REDIS_URL = 'redis://127.0.0.1'

if DEBUG:
    Config = DEV
else:
    Config = PRED


