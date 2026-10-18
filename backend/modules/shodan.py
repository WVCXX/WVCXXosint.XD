import shodan
from fastapi import HTTPException
API_KEY = ""
async def check_shodan(ip: str):
    try:
        api = shodan.Shodan(API_KEY)
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