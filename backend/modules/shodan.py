import shodan
from fastapi import HTTPException
from .config import SHODAN_API_KEY


async def check_shodan(ip: str):
    if not SHODAN_API_KEY:
        return {
            "title": "Shodan",
            "status": "info",
            "fields": [{"label": "Статус", "value": "Добавьте SHODAN_API_KEY в backend/.env"}],
        }
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)
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
    except shodan.APIError as e:
        return {
            "title": "Shodan",
            "status": "error",
            "fields": [{"label": "Ошибка", "value": str(e)}]
        }