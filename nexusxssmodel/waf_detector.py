import re
from typing import Dict, Optional
import aiohttp
from rich.console import Console

class WAFDetector:
    def __init__(self):
        self.console = Console()
        self.waf_signatures = {
            'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
            'ModSecurity': ['mod_security', 'NOYB'],
            'AWS WAF': ['x-amzn-RequestId', 'x-amz-cf-id'],
            'Akamai': ['akamai', 'ak_bmsc'],
            'Imperva': ['incap_ses', '_incapsula_'],
            'F5 BIG-IP': ['BigIP', 'F5', 'TS']
        }

    async def detect_waf(self, url: str) -> Optional[str]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    headers = dict(response.headers)
                    for waf_name, signatures in self.waf_signatures.items():
                        if any(sig.lower() in str(headers).lower() for sig in signatures):
                            self.console.print(f"[yellow]⚠️ WAF Detected: {waf_name}[/yellow]")
                            return waf_name
            return None
        except Exception as e:
            self.console.print(f"[red]Error in WAF detection: {str(e)}[/red]")
            return None