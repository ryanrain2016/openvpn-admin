from tortoise import models, fields
from datetime import datetime, timedelta

class Model(models.Model):
    class Meta:
        abstract=True

    date_format = '%Y-%m-%d'
    datetime_format = "%Y-%m-%d %H:%M:%S"

    @classmethod
    def _fields(cls):
        return ['id'] + list(cls._meta.fields)

    def to_dict(self):
        cls = self.__class__
        dic = {}
        for key in self._fields():
            cls_attr = getattr(cls, key)
            inst_attr = getattr(self, key)
            if isinstance(cls_attr, fields.DateField):
                if inst_attr:
                    # inst_attr = inst_attr.astimezone(cst_tz)
                    inst_attr = inst_attr.strftime(self.date_format)
            elif isinstance(cls_attr, fields.DatetimeField):
                if inst_attr:
                    # inst_attr = inst_attr.astimezone(cst_tz)
                    inst_attr = inst_attr.strftime(self.datetime_format)
            elif isinstance(cls_attr, fields.TimeDeltaField):
                if inst_attr:
                    inst_attr = inst_attr.total_seconds
            elif isinstance(cls_attr, fields.ForeignKeyField):
                key = key + '_id'
                inst_attr = getattr(self, key)
            elif isinstance(cls_attr, fields.ManyToManyField):
                continue
            dic[key] = inst_attr
        return dic

    @classmethod
    def from_dict(cls, dic):
        for key in cls._fields():
            cls_attr = getattr(cls, key)
            inst_attr = dic.get(key, cls_attr.default)
            if callable(inst_attr):
                inst_attr = inst_attr()
            if isinstance(cls_attr, fields.DateField):
                if cls_attr.auto_now_add:
                    inst_attr = datetime.now()
                else:
                    inst_attr = datetime.strptime(inst_attr, cls.date_format)
            elif isinstance(cls_attr, fields.DatetimeField):
                if cls_attr.auto_now_add:
                    inst_attr = datetime.now()
                else:
                    inst_attr = datetime.strptime(inst_attr, cls.datetime_format)
            elif isinstance(cls_attr, fields.TimeDeltaField):
                inst_attr = datetime.timedelta(seconds=inst_attr)
            elif isinstance(cls_attr, fields.ForeignKeyField):
                key = key + '_id'
                inst_attr = dic.get(key)
            elif isinstance(cls_attr, fields.ManyToManyField):
                continue
            dic[key] = inst_attr
        if dic['id'] is None:
            del dic['id']
        return cls(**dic)

    async def update(self, **args):
        dic = self.to_dict()
        dic.update(**args)
        obj = self.from_dict(dic)
        obj.id = self.id
        await obj.save()
        return obj

    async def replace(self, **args):
        args['id'] = self.id
        obj = self.from_dict(args)
        await obj.save()
        return obj

