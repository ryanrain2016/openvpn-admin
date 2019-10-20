from sanic import views, response
from sanic.request import Request
import asyncio
from tortoise.exceptions import DoesNotExist
import jwt
from inspect import isawaitable

class Pagination:
    page_size = 20

    async def get_data(self, queryset, page, page_size):
        offset = page * page_size - page_size
        items, total = await queryset.limit(page_size).offset(offset).all(), await queryset.count()
        return {
            'total': total,
            'items': [i.to_dict() for i in items]
        }

class BaseApi:
    model = None
    pagination_class = Pagination

    @classmethod
    def get_queryset(cls, request):
        qs = cls.model.all()
        order_by = request.args.get('order_by', None)
        if order_by:
            qs = qs.order_by(order_by)
        return qs

    @classmethod
    async def get_object(cls, pk=None):
        return await cls.model.get(pk=pk)

    @classmethod
    def register(cls, blueprint, name, prefix='/api'):
        endpoint_list = '%s/%s'%(prefix, name)
        endpoint_one = '%s/%s/<pk>'%(prefix, name)
        endpoint_one_action = '%s/%s/<pk>/<action>'%(prefix, name)
        blueprint.route(endpoint_list, methods=['GET', 'POST'])(lambda request:cls.dispatch(request))
        blueprint.route(endpoint_one, methods=['GET', 'PUT', 'PATCH', 'DELETE'])(lambda request, pk:cls.dispatch(request, pk))
        blueprint.route(endpoint_one_action, methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])(lambda request, pk, action:cls.dispatch(request, pk, action))

    @classmethod
    def verify_request(cls, request):
        auth = request.headers.get('Authorization')
        if not auth:
            token = request.args.get('token')
        else:
            token = auth.split().pop()
        if not token:
            return False
        secret = request.app.config['TOKEN_SECRET_KEY']
        ok, payload = verify_token(token, secret)
        if not ok:
            return False
        request['token_payload'] = payload
        return True

    @classmethod
    async def authorization(cls, request):
        return True

    @classmethod
    async def dispatch(cls, request:Request, pk=None, action=None):
        try:
            if not cls.verify_request(request):
                return response.text('', status=401)
        except:
            return response.text('', status=401)
        if not (await cls.authorization(request)):
            return response.text('', status=403)
        method = request.method.lower()
        if pk is None and method == 'get':
            method = 'getlist'
        handler = None
        if action is not None:
            handler = getattr(cls, action, None)
        if handler is None:
            handler = getattr(cls, method, None)
        if handler is None:
            return response.text('', status=405)
        if pk:
            ret = handler(request, pk)
        else:
            ret = handler(request)
        if isawaitable(ret):
            return await ret
        else:
            return ret

class GetListMixin:
    @classmethod
    async def getlist(cls, request, pk=None):
        if cls.pagination_class:
            params = request.args
            page = params.get('page', 1)
            page_size = params.get('page_size', cls.pagination_class.page_size)
            page, page_size = int(page), int(page_size)
            data = await cls.pagination_class().get_data(cls.get_queryset(request), page, page_size)
        else:
            data = await cls.get_queryset(request)
            data = [d.to_dict() for d in data]
        return response.json(data)


class GetMixin:
    @classmethod
    async def get(cls, request, pk=None):
        try:
            obj = await cls.get_object(pk)
        except DoesNotExist:
            return response.json({}, status=404)
        return response.json(obj.to_dict())

class PostMixin:
    @classmethod
    async def post(cls, request):
        params = request.form or request.json
        print(params)
        try:
            obj = cls.model(**params)
            await obj.save()
        except Exception as e:
            raise
            return response.json({}, status=400)
        return response.json(obj.to_dict(), status=201)

class PutMixin:
    @classmethod
    async def put(cls, request, pk=None):
        params = request.form or request.json
        try:
            obj = await cls.get_object(pk)
        except DoesNotExist:
            return response.json({}, status=404)
        obj = await obj.replace(**params)
        return response.json(obj.to_dict())

class PatchMixin:
    @classmethod
    async def patch(cls, request, pk=None):
        params = request.form or request.json
        try:
            obj = await cls.get_object(pk)
        except DoesNotExist:
            return response.json({}, status=404)
        obj = await obj.update(**params)
        return response.json(obj.to_dict())

class DeleteMixin:
    @classmethod
    async def delete(cls, request, pk=None):
        try:
            obj = await cls.get_object(pk)
        except DoesNotExist:
            return response.json({}, status=404)
        await obj.delete()
        return response.json(obj.to_dict())


class ReadMixin(GetListMixin, GetMixin):
    pass

class WriteMixin(PostMixin, PatchMixin, PutMixin):
    pass

def verify_token(token, secret):
    payload = jwt.decode(token, secret,  algorithms=['HS256'])
    if payload:
        return True, payload
    return False, {}


