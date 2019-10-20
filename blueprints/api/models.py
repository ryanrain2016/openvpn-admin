from tortoise import fields
from framework import models
from werkzeug.security import generate_password_hash,check_password_hash
from utils import to_md5

class User(models.Model):
    username = fields.CharField(max_length=32, unique=True)
    _password = fields.CharField(max_length=256)
    online = fields.BooleanField(default=False)
    ip = fields.CharField(max_length=64, blank=True, null=True)
    # remote_ip = fields.CharField(max_length=32, blank=True, null=True)
    trusted_host = fields.CharField(max_length=128, blank=True, null=True)
    last_online_at = fields.DatetimeField(auto_now=True)
    create_at = fields.DatetimeField(auto_now_add=True)

    def __init__(self, username, password=None, **kw):
        super().__init__(**kw)
        self.username = username
        if password:
            self.password = password

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self._password = generate_password_hash(value)

    def check_password(self, value):
        return check_password_hash(self.password, value)

class Log(models.Model):
    username = fields.CharField(max_length=32)
    ip = fields.CharField(max_length=64, blank=True, null=True)
    trusted_host = fields.CharField(max_length=128, blank=True, null=True)
    bytes_sent = fields.BigIntField(default=0)
    bytes_received = fields.BigIntField(default=0)
    online_time = fields.DatetimeField(null=True)
    offline_time = fields.DatetimeField(null=True)
