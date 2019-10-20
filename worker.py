import asyncio
import json
from aioredis.pubsub import Receiver
from utils import to_bytes, to_str

class BaseWorker:
    def __init__(self, handler, currency):
        self.handler = handler
        self.currency = currency
        self._running = False
        self._task = None

    async def iter_task(self):
        """
        异步迭代器
        """
        raise NotImplementedError

    async def publish(self, key, task):
        raise NotImplementedError
    
    async def stop(self):
        self._running = False
        if self._task:
            try:
                await self._task
            except asyncio.CancelledError:
                pass
    
    async def _run(self):
        tasks = set()
        async for task in self.iter_task():
            if len(tasks) < self.currency:
                tasks.add(asyncio.ensure_future(self.handler(*task)))
                continue
            _, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

    async def run(self):
        self._running = True
        async def daemon():
            while self._running:
                await asyncio.sleep(0.1)
        self._task = self._run()
        tasks = [daemon(), self._task]
        _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for p in pending:
            p.cancel()
        self._running = False

class RedisChannelWorker(BaseWorker):
    def __init__(self, handler, currency, redis, channel_names=None, channel_patterns=None):
        super().__init__(self, handler, currency)
        self.redis = redis
        self.q = asyncio.Queue()
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

    async def receiver_reader(self, receiver):
        async for channel, msg in receiver.iter():
            await self.q.put((msg, channel))

    async def iter_task(self):
        """
        异步迭代器
        """
        while True:
            yield self.q.get()
    
    def run(self):
        asyncio.ensure_future(self.producer())
        return super().run()

    async def publish(self, key, task):
        if isinstance(task, (list, tuple, dict)):
            task = json.dumps(task)
        await self.redis.publish(key, to_str(task))

class RedisListWorker(BaseWorker):
    def __init__(self, handler, currency, redis, list_keys=None):
        super().__init__(self, handler, currency)
        self.redis = redis
        self.q = asyncio.Queue()
        if isinstance(list_keys, str) and list_keys:
            list_keys = [list_keys]
        self.list_keys = list_keys or []

    async def iter_task(self):
        if not self.list_keys:
            return
        while True:
            key, msg = await self.redis.blpop(*self.list_keys)
            yield (msg, key)

    async def publish(self, key, task):
        if isinstance(task, (list, tuple, dict)):
            task = json.dumps(task)
        await self.redis.rpush(key, to_str(task))
        