import asyncio

import shodan
from .config import SHODAN_API_KEY


async def check_shodan(ip: str):
    if not SHODAN_API_KEY:
        return {
            "title": "Shodan",
            "status": "not_configured",
            "fields": [{"label": "Статус", "value": "Добавьте SHODAN_API_KEY в backend/.env"}],
        }
    try:
        api = shodan.Shodan(SHODAN_API_KEY, timeout=8)
        host = await asyncio.wait_for(asyncio.to_thread(api.host, ip), timeout=10)
        ports = ", ".join([str(p) for p in host.get('ports', [])[:5]])
        os = host.get('os', 'Неизвестно')
        org = host.get('org', 'Неизвестно')
        return {
            "title": "Shodan (Порты)",
            "status": "ok",
            "fields": [
                {"label": "IP", "value": ip},
                {"label": "Организация", "value": org},
                {"label": "ОС", "value": os},
                {"label": "Открытые порты", "value": ports + ("..." if len(host.get('ports', [])) > 5 else "")}
            ]
        }
    except shodan.APIError as error:
        return {
            "title": "Shodan",
            "status": "rate_limited" if "limit" in str(error).lower() else "error",
            "fields": [{"label": "Ошибка", "value": "Shodan API request failed"}]
        }
    except asyncio.TimeoutError:
        return {
            "title": "Shodan",
            "status": "error",
            "fields": [{"label": "Ошибка", "value": "Shodan превысил лимит времени"}],
        }