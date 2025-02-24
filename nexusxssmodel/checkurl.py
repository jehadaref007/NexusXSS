import aiohttp
from typing import Dict, Any
from rich.console import Console

class ModernURLChecker:
    def __init__(self):
        self.console = Console()

    async def verify_url(self, url: str) -> Dict[str, Any]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    return {
                        'is_valid': 200 <= response.status < 400,
                        'status': response.status,
                        'content_type': response.headers.get('content-type', '')
                    }
        except Exception as e:
            self.console.print(f"[red]Invalid URL: {url}[/red]")  # تغيير لون رسالة الخطأ إلى الأحمر
            return {
                'is_valid': False,
                'status': 0,
                'error': str(e)
            }
