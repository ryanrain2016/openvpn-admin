# from .api import verify_token, get_token
from inspect import isawaitable
from aioredis.pubsub import Receiver

import asyncio

class BaseWebsocket:
    def __init__(self, request, ws, handler):
        self.request = request
        self.ws = ws
        self.handler = handler

    async def consumer(self):
        while True:
            try:
                msg = await asyncio.wait_for(self.ws.recv(), timeout=20)
            except asyncio.TimeoutError:
                try:
                    pong_waiter = await self.ws.ping()
                    await asyncio.wait_for(pong_waiter, timeout=10)
                except asyncio.TimeoutError:
                    break
            except Exception as e:
                print(e)
                break
            else:
                await self.msg_received(msg)

    async def msg_received(self, msg):
        ret = self.handler(msg)
        if isawaitable(ret):
            ret = await ret
        return ret

    async def __call__(self):
        if not await self.pre_handle():
            return
        done, pending = await asyncio.wait(
            {self.consumer(), self.producer()},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
            try:
                await task
            except:
                pass
        await self.finished()

    @property
    def closed(self):
        return self.ws.closed

    async def send(self, msg):
        if not self.closed:
            await self.ws.send(msg)

    async def finished(self):
        if not self.closed:
            await self.ws.close()
        print('finished:', self.ws)

    async def producer(self):
        """
        应该异步阻塞或者非独占死循环，返回后连接中止
        """
        pass

    async def pre_handle(self):
        return True

class RedisChannelWebsocket(BaseWebsocket):
    def __init__(self, request, ws, handler, channel_names=None, channel_patterns=None):
        self.request = request
        self.ws = ws
        self.handler = handler
        if isinstance(channel_names, str) and channel_names:
            channel_names = [channel_names]
        if isinstance(channel_patterns, str) and channel_patterns:
            channel_patterns = [channel_patterns]
        self.channel_names = channel_names
        self.channel_patterns = channel_patterns

    async def producer(self):
        channel_names = self.channel_names or []
        channel_patterns = self.channel_patterns or []
        if not channel_names and not channel_patterns:
            return
        self.redis = await self.request.app.get_redis()
        mpsc = Receiver()
        if channel_names:
            channels = [mpsc.channel(c) for c in channel_names]
            await self.redis.subscribe(*channels)
        if channel_patterns:
            tasks = set()
            for p in channel_patterns:
                tasks.add(self.redis.psubscribe(mpsc.pattern(p)))
            if tasks:
                await asyncio.wait(tasks)
        try:
            await self.receiver_reader(mpsc)
        finally:
            if channel_names:
                await self.redis.unsubscribe(*channel_names)
            if channel_patterns:
                tasks = set()
                for p in channel_patterns:
                    tasks.add(self.redis.punsubscribe(p))
                await asyncio.wait(tasks)
            mpsc.stop()

    async def pre_send(self, msg):
        return msg

    async def receiver_reader(self, receiver):
        async for channel, msg in receiver.iter():
            msg = await self.pre_send(msg)
            if msg:
                await self.send(msg)

class RedisListWebsocket(BaseWebsocket):
    def __init__(self, request, ws, handler, list_keys=None):
        self.request = request
        self.ws = ws
        self.handler = handler
        if isinstance(list_keys, str) and list_keys:
            list_keys = [list_keys]
        self.list_keys = list_keys or []

    async def pre_send(self, msg):
        return msg

    async def producer(self):
        if not self.list_keys:
            return
        self.redis = await self.request.app.get_redis()
        try:
            while True:
                key, msg = await self.redis.blpop(*self.list_keys)
                msg = await self.pre_send(msg)
                if msg:
                    await self.send(msg)
        finally:
            pass


if __name__ == "__main__":
    pass

