from werkzeug.security import generate_password_hash,check_password_hash
from tortoise import fields
from framework import models
from utils import to_md5
import time

class AdminUser(models.Model):
    username = fields.CharField(max_length=32, unique=True)
    _password = fields.CharField(max_length=256)

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
        value = to_md5(value)
        self._password = generate_password_hash(value)

    def check_password(self, value):
        value = to_md5(value)
        return check_password_hash(self.password, value)


