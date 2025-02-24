import asyncio
from playwright.async_api import async_playwright
from rich.console import Console
import os

class ScreenshotCapture:
    def __init__(self):
        self.console = Console()
        self.screenshots_dir = "vulnerability_screenshots"
        os.makedirs(self.screenshots_dir, exist_ok=True)

    async def capture(self, url: str, vulnerability_id: str) -> str:
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                page = await browser.new_page()
                await page.goto(url)
                filename = f"{self.screenshots_dir}/vuln_{vulnerability_id}.png"
                await page.screenshot(path=filename)
                await browser.close()
                return filename
        except Exception as e:
            self.console.print(f"[red]Screenshot error: {str(e)}[/red]")
            return None