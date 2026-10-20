import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
