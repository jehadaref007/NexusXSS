__version__ = "2.0.0"
__author__ = "Jehad Mosa"
__date__ = "2025-02-24"
__description__ = "Advanced Cross-Site Scripting Detection Tool"

from .scanner import ModernXSSScanner
from .reporting import ModernReportGenerator
from .checkurl import ModernURLChecker
from .rate_limiter import RateLimiter

def show_banner():
    return """[bold blue]
    ╔══════════════════════════════════════════════════╗
    ║          [cyan]Developed by: Jehad Mosa[/cyan]   ║
    ║          [yellow]Nexus XSS v2.0.0[/yellow]       ║
    ║          [cyan]Developed by: Jehad Mosa[/cyan]   ║
    ║          [green]Release Date: 2025-02-24[/green] ║
    ╚══════════════════════════════════════════════════╝[/bold blue]
    """
