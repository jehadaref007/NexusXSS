from pydantic_settings import BaseSettings
from typing import List, Optional
import os
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    """
    Application configuration settings
    
    Attributes:
        LOG_LEVEL (str): Logging level (DEBUG, INFO, WARNING, ERROR)
        TIMEOUT (int): Request timeout in seconds
        MAX_RETRIES (int): Maximum number of retry attempts for failed requests
        THREADS (int): Number of concurrent scanning threads
        OUTPUT_DIR (str): Directory for saving reports
        RATE_LIMIT (int): Maximum requests per second
        AUTH_TOKEN (Optional[str]): Authentication token for protected sites
        PROXY_URL (Optional[str]): Proxy server URL if needed
    """
    
    LOG_LEVEL: str = "INFO"
    TIMEOUT: int = 30
    MAX_RETRIES: int = 3
    THREADS: int = 10
    OUTPUT_DIR: str = "reports"
    RATE_LIMIT: int = 10  # New: Rate limiting
    AUTH_TOKEN: Optional[str] = None  # New: Authentication support
    PROXY_URL: Optional[str] = None   # New: Proxy support
    
    USER_AGENTS: List[str] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
    ]

    class Config:
        env_prefix = "NEXUSXSS_"
        env_file = ".env"

settings = Settings()

PROXY_LIST = [
    "socks5://127.0.0.1:9050",  # Tor
    "http://proxy1.example.com:8080",
    "http://proxy2.example.com:8080"
]