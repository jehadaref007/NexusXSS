import time
import random
import asyncio
from .config import settings

class RateLimiter:
    def __init__(self, min_delay: float = 0.5, max_delay: float = 2.0):
        self.last_request = 0
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.requests_per_second = settings.RATE_LIMIT
        
    async def wait(self):
        """
        Implements intelligent rate limiting with dynamic delays
        """
        now = time.time()
        delay = random.uniform(self.min_delay, self.max_delay)
        
        # Ensure we don't exceed the rate limit
        if self.requests_per_second > 0:
            min_interval = 1.0 / self.requests_per_second
            delay = max(delay, min_interval)
            
        if now - self.last_request < delay:
            await asyncio.sleep(delay)
        self.last_request = now