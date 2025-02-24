# Nexus XSS - Advanced Cross-Site Scripting Scanner

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

Nexus XSS is a cutting-edge Cross-Site Scripting (XSS) vulnerability scanner designed for penetration testers and security professionals. It offers a robust set of features for comprehensive web application security assessments, including advanced evasion techniques and detailed reporting.

## Key Features

* **Multi-threaded Scanning:** Efficiently scan multiple URLs concurrently.
* **Advanced Evasion:** Bypass WAFs and security filters with customizable evasion levels.
* **Anonymity:** Utilize proxies and the Tor network for anonymous scanning.
* **Custom Payloads:** Leverage custom payloads for targeted testing.
* **Detailed Reporting:** Generate comprehensive reports in HTML, JSON, and TXT formats.
* **Flexible Configuration:** Fine-tune scans with various options for threads, timeouts, and delays.
* **User-Agent Rotation:** Automatically rotate User-Agents to mimic real user traffic.
* **Multiple Scan Modes:** Choose between fast, normal, and thorough scanning modes.

## Installation

### Prerequisites

* Python 3.6+
* `pip` (Python package installer)

### Installation Steps

1.  **Clone the repository:**

    ```bash
    git clone [repository link]
    cd NexusXSS
    ```

2.  **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

    * Alternatively, install the required packages manually:

        ```bash
        pip install aiohttp rich pydantic_settings python-dotenv requests
        ```

        * `aiohttp`: Asynchronous HTTP client/server framework.
        * `rich`: Rich text and beautiful formatting in the terminal.
        * `pydantic_settings`: Settings management using Pydantic.
        * `python-dotenv`: Loads environment variables from a `.env` file.
        * `requests`: Simple HTTP library for Python.

## Usage

### Basic Commands

* **Scan a single URL:**

    ```bash
    python NexusXSS.py -u "[https://example.com/page?q=XSS](https://example.com/page?q=XSS)"
    ```

* **Scan URLs from a file:**

    ```bash
    python NexusXSS.py -f urls.txt
    ```

* **Fast scan mode:**

    ```bash
    python NexusXSS.py -u "[https://example.com/page?q=XSS](https://example.com/page?q=XSS)" --mode fast
    ```

### Advanced Commands

* **High evasion level:**

    ```bash
    python NexusXSS.py -u "URL" --evasion-level high
    ```

* **Use a proxy:**

    ```bash
    python NexusXSS.py -u "URL" --proxy "[تمت إزالة عنوان URL غير صالح]"
    ```

* **Use Tor:**

    ```bash
    python NexusXSS.py -u "URL" --tor
    ```

* **Custom payloads:**

    ```bash
    python NexusXSS.py -u "URL" --custom-payloads payloads.txt
    ```

* **Detailed report (HTML):**

    ```bash
    python NexusXSS.py -u "URL" --format html -o report.html
    ```

* **Verbose output:**

    ```bash
    python NexusXSS.py -u "URL" --verbose
    ```

* **Customize threads and delay:**

    ```bash
    python NexusXSS.py -u "URL" --threads 20 --delay 1.0
    ```

* **Advanced mode with random User-Agent:**

    ```bash
    python NexusXSS.py -u "URL" --advanced-mode --random-agent
    ```

### Help

```bash 
python NexusXSS.py --help

usage: NexusXSS.py [-h] [-u URL] [-f FILE] [--mode {fast,normal,thorough}] [--advanced-mode]
                    [--evasion-level {low,medium,high}] [--random-agent] [--proxy PROXY] [--tor] [-o OUTPUT]
                    [--format {html,json,txt}] [--threads THREADS] [--timeout TIMEOUT] [--delay DELAY]
                    [--custom-payloads CUSTOM_PAYLOADS] [-v] [-q]

Nexus XSS - Advanced Cross-Site Scripting Scanner

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL with XSS marker
  -f FILE, --file FILE  File containing multiple URLs
  --mode {fast,normal,thorough}
                        Scanning mode
  --advanced-mode       Enable advanced scanning techniques
  --evasion-level {low,medium,high}
                        Evasion technique level
  --random-agent        Use random User-Agent
  --proxy PROXY         Use proxy (e.g., http://127.0.0.1:8080)
  --tor                 Use Tor network for scanning
  -o OUTPUT, --output OUTPUT
                        Output file path
  --format {html,json,txt}
                        Report format
  --threads THREADS     Number of concurrent threads
  --timeout TIMEOUT     Request timeout in seconds
  --delay DELAY         Delay between requests
  --custom-payloads CUSTOM_PAYLOADS
                        Path to custom payloads file
  -v, --verbose         Enable verbose output
  -q, --quiet           Suppress all output except results
