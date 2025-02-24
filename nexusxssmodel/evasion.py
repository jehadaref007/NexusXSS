from typing import List
import random

class EvasionTechniques:
    @staticmethod
    def get_random_user_agent() -> str:
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
            "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
            "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36"
        ]
        return random.choice(agents)
    
    @staticmethod
    def get_random_headers() -> dict:
        return {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": EvasionTechniques.get_random_user_agent(),
            "X-Forwarded-For": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        }