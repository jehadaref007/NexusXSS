from typing import List, Dict
import logging
from playwright.async_api import async_playwright
from rich.console import Console

class DOMScanner:
    def __init__(self):
        self.console = Console()
        self.dangerous_sinks = [
            'document.write',
            'innerHTML',
            'outerHTML',
            'eval',
            'setTimeout',
            'setInterval',
            'location',
            'src',
            'href'
        ]

    async def scan_dom(self, url: str) -> List[Dict]:
        vulnerabilities = []
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                page = await browser.new_page()
                
                # Monitor console for JavaScript errors
                page.on("console", lambda msg: self._handle_console(msg, vulnerabilities))
                
                # Monitor DOM mutations
                await page.evaluate("""
                    new MutationObserver(function(mutations) {
                        mutations.forEach(function(mutation) {
                            if (mutation.type === 'childList') {
                                window.domMutated = true;
                            }
                        });
                    }).observe(document, { childList: true, subtree: true });
                """)
                
                await page.goto(url)
                await page.wait_for_timeout(2000)  # Wait for dynamic content

                # Check for dangerous sink usage
                dangerous_sinks_found = await page.evaluate("""
                    () => {
                        return Array.from(document.querySelectorAll('script')).map(script => {
                            return script.textContent;
                        }).join('\\n');
                    }
                """)

                for sink in self.dangerous_sinks:
                    if sink in dangerous_sinks_found:
                        vulnerabilities.append({
                            'type': 'DOM-based XSS',
                            'sink': sink,
                            'severity': 'High',
                            'description': f'Dangerous DOM sink found: {sink}'
                        })

                await browser.close()
                return vulnerabilities

        except Exception as e:
            self.console.print(f"[red]DOM scanning error: {str(e)}[/red]")
            return []