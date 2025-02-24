import aiohttp
import asyncio
from datetime import datetime
from .reporting import ScanResult
from typing import Optional, Tuple
from rich.console import Console
from rich.panel import Panel  # إضافة import للـ Panel
from .payloads import PayloadObfuscator
from .evasion import EvasionTechniques
import random
import time
from .rate_limiter import RateLimiter

class ModernXSSScanner:
    def __init__(self, max_retries: int = 3, timeout: int = 30):
        self.session = None
        self.max_retries = max_retries
        self.timeout = timeout
        self.console = Console()
        self.obfuscator = PayloadObfuscator()
        self.evasion = EvasionTechniques()
        self.delay_range = (1, 3)  # Random delay between requests
        self.rate_limiter = RateLimiter()  # إضافة RateLimiter
        
    async def setup(self):
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.setup()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def scan_url(self, url: str, payload: str) -> ScanResult:
        """Enhanced XSS scanning with improved detection and evasion"""
        for attempt in range(self.max_retries):
            try:
                # استخدام rate limiter قبل كل طلب
                await self.rate_limiter.wait()
                
                # Random delay between requests
                await asyncio.sleep(random.uniform(*self.delay_range))
                
                # Apply random obfuscation technique
                obfuscation_methods = [
                    self.obfuscator.hex_encode,
                    self.obfuscator.unicode_encode,
                    self.obfuscator.base64_encode,
                    self.obfuscator.mixed_case,
                    self.obfuscator.add_random_spaces
                ]
                
                modified_payload = random.choice(obfuscation_methods)(payload)
                
                # Add evasion headers
                headers = self.evasion.get_random_headers()
                
                # Add unique identifier to help track successful injections
                tracking_id = f"nexusxss_{datetime.now().timestamp()}"
                modified_payload = payload.replace("alert(1)", f"alert('{tracking_id}')")
                
                target_url = url.replace("XSS", modified_payload)
                async with self.session.get(
                    target_url, 
                    headers=headers,
                    ssl=False  # يتجاهل شهادات SSL
                ) as response:
                    content = await response.text()
                    
                    # Enhanced reflection analysis
                    is_vulnerable, reflection_details = self._analyze_reflection(content, modified_payload)
                    
                    if is_vulnerable:
                        self.console.print(f"[bold green]Found XSS vulnerability![/bold green]")
                        self.console.print(Panel.fit(
                            f"[red]Vulnerable URL:[/red] {target_url}\n"
                            f"[yellow]Payload:[/yellow] {payload}\n"
                            f"[cyan]Reflection Context:[/cyan] {reflection_details}",
                            title="🎯 XSS Found!",
                            border_style="red"
                        ))
                    
                    return ScanResult(
                        url=target_url,
                        vulnerable=is_vulnerable,
                        payload=payload,
                        timestamp=datetime.now(),
                        response_code=response.status,
                        reflection_point=reflection_details,
                        severity=self._determine_severity(is_vulnerable, content)
                    )
                    
            except Exception as e:
                if attempt == self.max_retries - 1:
                    self.console.print(f"[red]Error scanning {url}: {str(e)}[/red]")
                    return ScanResult(
                        url=url,
                        vulnerable=False,
                        payload=payload,
                        timestamp=datetime.now(),
                        response_code=0,
                        reflection_point="",
                        severity="Error"
                    )
                await asyncio.sleep(1)
    
    def _analyze_reflection(self, content: str, payload: str) -> Tuple[bool, str]:
        """Enhanced reflection analysis with context awareness"""
        content_lower = content.lower()
        payload_lower = payload.lower()
        
        # Check for direct reflection
        if payload_lower in content_lower:
            try:
                idx = content_lower.index(payload_lower)
                context_start = max(0, idx - 50)
                context_end = min(len(content), idx + len(payload) + 50)
                context = content[context_start:context_end]
                
                # Check for dangerous contexts
                dangerous_contexts = {
                    "script": 10,    # Highest priority
                    "onerror": 9,
                    "onload": 9,
                    "onclick": 8,
                    "onmouseover": 8,
                    "onfocus": 8,
                    "onmouseout": 8,
                    "javascript:": 7,
                    "data:": 6,
                    "src=": 5,
                    "href=": 5,
                    "<img": 4,
                    "<svg": 4,
                    "<iframe": 4,
                    "<div": 3,
                    "<input": 3
                }
                
                for ctx, severity in dangerous_contexts.items():
                    if ctx in content_lower[max(0, idx-20):idx+len(payload)+20]:
                        return True, f"Found in {ctx} context: {context}"  # تصحيح تنسيق النص
                
                # تحسين التحقق من الترميز
                special_chars = ["<", ">", "'", '"']
                if not any(f"&{char};" in content_lower for char in special_chars):
                    if any(char in content for char in special_chars):
                        return True, f"Unencoded special characters found: {context}"
                        
            except ValueError:
                pass
                
        return False, ""
    
    def _determine_severity(self, is_vulnerable: bool, content: str) -> str:
        """Determine the severity of the vulnerability"""
        if not is_vulnerable:
            return "Safe"
            
        content_lower = content.lower()
        if "<script" in content_lower or "javascript:" in content_lower:
            return "Critical"
        elif "onerror=" in content_lower or "onload=" in content_lower:
            return "High"
        elif "<img" in content_lower or "<svg" in content_lower:
            return "Medium"
        return "Low"
