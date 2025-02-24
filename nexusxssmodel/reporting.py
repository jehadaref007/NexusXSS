import os
import json
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List
from rich.table import Table
from rich.panel import Panel

@dataclass
class ScanResult:
    url: str
    vulnerable: bool
    payload: str
    timestamp: datetime
    response_code: int
    reflection_point: str
    severity: str = "High"

class ModernReportGenerator:
    def __init__(self):
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_html(self, results: List[ScanResult]) -> str:
        """Generate HTML report from scan results"""
        css_styles = """
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
                    margin: 20px;
                    background-color: #f5f5f5;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                table {
                    border-collapse: collapse;
                    width: 100%;
                    margin-top: 20px;
                }
                th, td {
                    border: 1px solid #ddd;
                    padding: 12px;
                    text-align: left;
                }
                th {
                    background-color: #f8f9fa;
                }
                .vulnerable {
                    color: #dc3545;
                    font-weight: bold;
                }
                .safe {
                    color: #28a745;
                    font-weight: bold;
                }
                .summary {
                    margin-bottom: 30px;
                    padding: 20px;
                    background: #f8f9fa;
                    border-radius: 4px;
                }
            </style>
        """
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>NexusXSS Scan Report</title>
            {css_styles}
        </head>
        <body>
            <div class="container">
                <h1>NexusXSS Scan Report</h1>
                <div class="summary">
                    <h2>Summary</h2>
                    <p>Total URLs Tested: {len(results)}</p>
                    <p>Vulnerabilities Found: {sum(1 for r in results if r.vulnerable)}</p>
                    <p>Safe URLs: {sum(1 for r in results if not r.vulnerable)}</p>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>URL</th>
                            <th>Payload</th>
                            <th>Response Code</th>
                            <th>Severity</th>
                            <th>Reflection Point</th>
                        </tr>
                    </thead>
                    <tbody>
        """

        for result in results:
            status_class = "vulnerable" if result.vulnerable else "safe"
            status_text = "Vulnerable" if result.vulnerable else "Safe"
            
            html_content += f"""
                        <tr>
                            <td class="{status_class}">{status_text}</td>
                            <td>{result.url}</td>
                            <td>{result.payload}</td>
                            <td>{result.response_code}</td>
                            <td>{result.severity}</td>
                            <td>{result.reflection_point}</td>
                        </tr>
            """

        html_content += """
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        return html_content

    def generate_json(self, results: List[ScanResult]) -> str:
        """Generate JSON report from scan results"""
        return json.dumps([
            {
                'url': r.url,
                'vulnerable': r.vulnerable,
                'payload': r.payload,
                'timestamp': r.timestamp.isoformat(),
                'response_code': r.response_code,
                'reflection_point': r.reflection_point,
                'severity': r.severity
            }
            for r in results
        ], indent=2)
    
    def save_report(self, results: List[ScanResult], format: str = "html") -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.report_dir}/report_{timestamp}.{format}"
        
        if format == "html":
            content = self.generate_html(results)
        else:
            content = self.generate_json(results)
            
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        return filename

    def display_results(self, results: List[ScanResult], console):
        """Display scan results with improved formatting"""
        # Create summary panel
        total = len(results)
        vulnerable = sum(1 for r in results if r.vulnerable)
        safe = total - vulnerable
        
        console.print(Panel.fit(
            f"[white]Total URLs Tested: [blue]{total}[/blue][/white]\n"
            f"[white]Vulnerabilities Found: [red]{vulnerable}[/red][/white]\n"
            f"[white]Safe URLs: [green]{safe}[/green][/white]",
            title="🎯 Scan Summary",
            border_style="blue"
        ))

        # Create results table with improved formatting
        table = Table(
            title="🔍 XSS Scan Results",
            show_header=True,
            header_style="bold cyan",
            border_style="blue"
        )
        
        table.add_column("Status", style="bold", width=12)
        table.add_column("URL", style="cyan")
        table.add_column("Payload", style="yellow")
        table.add_column("Response", justify="center", width=8)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Reflection Point", style="dim")

        for result in results:
            if result.vulnerable:
                # Highlight vulnerable results
                status = "[bold red]✘ Vulnerable[/bold red]"
                severity = f"[bold red]{result.severity}[/bold red]"
                # Show special panel for vulnerable findings
                console.print(Panel.fit(
                    f"[red]Vulnerable URL:[/red] {result.url}\n"
                    f"[yellow]Payload:[/yellow] {result.payload}\n"
                    f"[cyan]Reflection Point:[/cyan] {result.reflection_point}\n"
                    f"[magenta]Severity:[/magenta] {result.severity}",
                    title="🚨 Vulnerability Found!",
                    border_style="red"
                ))
            else:
                status = "[bold green]✓ Safe[/bold green]"
                severity = f"[green]{result.severity}[/green]"

            table.add_row(
                status,
                result.url,
                result.payload,
                str(result.response_code),
                severity,
                result.reflection_point or "-"
            )

        console.print("\n")
        console.print(table)
        
        # If vulnerabilities found, show a warning message
        if vulnerable > 0:
            console.print(Panel.fit(
                f"[bold red]⚠️ Found {vulnerable} potential XSS vulnerabilities![/bold red]\n"
                "[yellow]Please check the HTML report for detailed information.[/yellow]",
                border_style="red"
            ))
