import os
import json
import tempfile
import threading
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

API_KEY_ENV = {
	"github": "GITHUB_TOKEN",
	"hibp": "HIBP_API_KEY",
	"shodan": "SHODAN_API_KEY",
	"virustotal": "VIRUSTOTAL_API_KEY",
	"abuseipdb": "ABUSEIPDB_API_KEY",
	"censys_id": "CENSYS_API_ID",
	"censys_secret": "CENSYS_API_SECRET",
	"urlscan": "URLSCAN_API_KEY",
	"search": "SEARCH_API_KEY",
}
IMPLEMENTED_API_ADAPTERS = {"github", "hibp", "shodan"}
SETTINGS_PATH = Path(__file__).resolve().parents[1] / "settings.json"
_SETTINGS_LOCK = threading.RLock()


def _read_saved_settings() -> dict[str, str]:
	try:
		value = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
	except FileNotFoundError:
		return {}
	except (OSError, json.JSONDecodeError):
		return {}
	if not isinstance(value, dict):
		return {}
	return {
		name: token
		for name, token in value.items()
		if name in API_KEY_ENV and isinstance(token, str) and token
	}


def get_api_key(provider: str) -> str:
	env_name = API_KEY_ENV.get(provider)
	if env_name is None:
		raise ValueError("Unknown API key provider")
	with _SETTINGS_LOCK:
		return _read_saved_settings().get(provider, os.getenv(env_name, ""))


def set_api_key(provider: str, value: str) -> None:
	if provider not in API_KEY_ENV:
		raise ValueError("Unknown API key provider")
	token = value.strip()
	if not token or len(token) > 4096:
		raise ValueError("API key must contain 1 to 4096 characters")
	with _SETTINGS_LOCK:
		settings = _read_saved_settings()
		settings[provider] = token
		_write_saved_settings(settings)


def clear_api_key(provider: str) -> None:
	if provider not in API_KEY_ENV:
		raise ValueError("Unknown API key provider")
	with _SETTINGS_LOCK:
		settings = _read_saved_settings()
		settings.pop(provider, None)
		_write_saved_settings(settings)


def get_api_key_statuses() -> list[dict[str, str | bool]]:
	with _SETTINGS_LOCK:
		saved = _read_saved_settings()
		return [
			{
				"provider": provider,
				"configured": bool(saved.get(provider) or os.getenv(env_name, "")),
				"source": "application" if saved.get(provider) else "environment" if os.getenv(env_name, "") else "none",
				"adapter_implemented": provider in IMPLEMENTED_API_ADAPTERS,
			}
			for provider, env_name in API_KEY_ENV.items()
		]


def _write_saved_settings(settings: dict[str, str]) -> None:
	SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
	fd, temporary_path = tempfile.mkstemp(prefix=".settings-", dir=SETTINGS_PATH.parent)
	try:
		os.fchmod(fd, 0o600)
		with os.fdopen(fd, "w", encoding="utf-8") as settings_file:
			json.dump(settings, settings_file)
			settings_file.flush()
			os.fsync(settings_file.fileno())
		os.replace(temporary_path, SETTINGS_PATH)
		os.chmod(SETTINGS_PATH, 0o600)
	finally:
		if os.path.exists(temporary_path):
			os.unlink(temporary_path)
