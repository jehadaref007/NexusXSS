import asyncio
from asyncio import Semaphore
from itertools import chain
import platform
from nexusxssmodel import ModernXSSScanner, ModernReportGenerator, show_banner  # أضف show_banner هنا
from nexusxssmodel.checkurl import ModernURLChecker
from nexusxssmodel.config import settings
from typing import List
import logging
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.table import Table
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.align import Align
import argparse
from nexusxssmodel.waf_detector import WAFDetector
from nexusxssmodel.screenshot import ScreenshotCapture
from nexusxssmodel.dom_scanner import DOMScanner

if platform.system() == 'Windows':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

console = Console()

class NexusXSSController:
    def __init__(self):
        self.scanner = ModernXSSScanner(
            max_retries=settings.MAX_RETRIES,
            timeout=settings.TIMEOUT
        )
        self.url_checker = ModernURLChecker()
        self.report_generator = ModernReportGenerator()
        self.rate_limiter = Semaphore(settings.RATE_LIMIT)
        self.waf_detector = WAFDetector()
        self.screenshot_capture = ScreenshotCapture()
        self.dom_scanner = DOMScanner()
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            level=settings.LOG_LEVEL,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='nexusxss.log'
        )

    async def scan_with_rate_limit(self, url: str, payload: str):
        """Execute scan with rate limiting"""
        async with self.rate_limiter:
            result = await self.scanner.scan_url(url, payload)
            await asyncio.sleep(1.0 / settings.RATE_LIMIT)  # Ensure rate limiting
            return result

    async def run_scan(self, urls: List[str], payloads: List[str]):
        await self.scanner.setup()
        
        # Check for WAF
        for url in urls:
            waf = await self.waf_detector.detect_waf(url)
            if waf:
                console.print(f"[yellow]WAF detected ({waf}) - Adjusting scan parameters...[/yellow]")
        
        # Scan for DOM-based XSS
        dom_results = []
        for url in urls:
            dom_vulns = await self.dom_scanner.scan_dom(url)
            if dom_vulns:
                dom_results.extend(dom_vulns)
                console.print("[red]DOM-based XSS vulnerabilities found![/red]")

        # Improved parallel scanning with chunking
        chunk_size = 50  # Adjust based on memory constraints
        results = []
        
        async def process_chunk(chunk):
            tasks = [
                self.scan_with_rate_limit(url, payload)
                for url, payload in chunk
            ]
            return await asyncio.gather(*tasks)

        # Create chunks of URL/payload combinations
        combinations = list(chain.from_iterable(
            [(url, payload) for payload in payloads]
            for url in urls
        ))
        
        chunks = [combinations[i:i + chunk_size] 
                 for i in range(0, len(combinations), chunk_size)]

        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(combinations))
            
            for chunk in chunks:
                chunk_results = await process_chunk(chunk)
                results.extend(chunk_results)
                progress.update(task, advance=len(chunk))

        # Capture screenshots for vulnerabilities
        for result in results:
            if result.vulnerable:
                screenshot = await self.screenshot_capture.capture(result.url, result.id)
                if screenshot:
                    result.screenshot = screenshot

        return results

def setup_args():
    parser = argparse.ArgumentParser(
        description="Nexus XSS - Advanced Cross-Site Scripting Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Main arguments
    parser.add_argument('-u', '--url', help='Target URL with XSS marker')
    parser.add_argument('-f', '--file', help='File containing multiple URLs')
    
    # Scan modes
    parser.add_argument('--mode', choices=['fast', 'normal', 'thorough'], 
                       default='normal', help='Scanning mode')
    parser.add_argument('--advanced-mode', action='store_true', 
                       help='Enable advanced scanning techniques')
    
    # Evasion options
    parser.add_argument('--evasion-level', choices=['low', 'medium', 'high'],
                       default='medium', help='Evasion technique level')
    parser.add_argument('--random-agent', action='store_true',
                       help='Use random User-Agent')
    
    # Proxy options
    parser.add_argument('--proxy', help='Use proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--tor', action='store_true',
                       help='Use Tor network for scanning')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('--format', choices=['html', 'json', 'txt'],
                       default='html', help='Report format')
    
    # Advanced options
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of concurrent threads')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Request timeout in seconds')
    parser.add_argument('--delay', type=float, default=0.5,
                       help='Delay between requests')
    parser.add_argument('--custom-payloads', help='Path to custom payloads file')
    
    # Verbosity
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Suppress all output except results')
    
    return parser.parse_args()

# في بداية الدالة main في ملف main.py
async def main():
    try:
        args = setup_args()
        banner = show_banner()
        console.print(f"\n{banner}\n")

        urls = []
        if args.url:
            urls.append(args.url)
        elif args.file:
            with open(args.file, 'r') as f:
                urls.extend(line.strip() for line in f if line.strip())
        else:
            # Only show URL prompt if no command line arguments provided
            console.print(Panel.fit(
                "[cyan]Enter target URL with 'XSS' as injection point[/cyan]\n"
                "[white]Examples:[/white]\n"
                "1. [green]https://example.com/search?q=XSS[/green]\n"
                "2. [green]https://example.com/page?param=XSS[/green]",
                title="Target URL",
                border_style="blue"
            ))
            urls.append(input("\nURL: ").strip())

        # Load payloads
        if args.custom_payloads:
            payload_file = args.custom_payloads
        else:
            payload_file = "wordlist.txt"

        with open(payload_file, "r") as f:
            payloads = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        # Configure scanner based on arguments
        scanner_config = {
            'max_retries': args.threads,
            'timeout': args.timeout,
            'delay': args.delay,
            'mode': args.mode,
            'evasion_level': args.evasion_level,
            'use_random_agent': args.random_agent,
            'proxy': args.proxy if args.proxy else (settings.PROXY_URL if args.tor else None)
        }

        console.print("\n[bold blue]Starting scan...[/bold blue]\n")

        controller = NexusXSSController()
        results = await controller.run_scan(urls, payloads)

        # Generate and display report
        report_gen = ModernReportGenerator()
        report_gen.display_results(results, console)
        
        # Save reports
        if args.output:
            report_file = report_gen.save_report(results, args.format)
            console.print(Panel.fit(
                f"[green]Report saved:[/green] {report_file}",
                title="Report Saved",
                border_style="green"
            ))

    except Exception as e:
        console.print(Panel.fit(
            f"[red]Error: {str(e)}[/red]",
            title="❌ Error",
            border_style="red"
        ))
        if args.verbose:
            logging.error(f"Unexpected error: {str(e)}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(main())