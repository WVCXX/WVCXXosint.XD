import asyncio
import logging
import whois
logger = logging.getLogger(__name__)
async def check_whois(domain: str):
    try:
        w = await asyncio.wait_for(asyncio.to_thread(whois.whois, domain), timeout=10)
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        return {
            "title": "WHOIS Домена",
            "status": "completed",
            "fields": [
                {"label": "Регистратор", "value": str(w.registrar or "Неизвестно")},
                {"label": "Дата создания", "value": str(creation or "Неизвестно")},
                {"label": "Страна", "value": str(w.country or "Неизвестно")}
            ]
        }
    except asyncio.TimeoutError:
        logger.warning("WHOIS lookup timed out for %s", domain)
        return {"title": "WHOIS Домена", "status": "error", "fields": [{"label": "Ошибка", "value": "WHOIS превысил лимит времени"}]}
    except Exception:
        logger.exception("WHOIS lookup failed for %s", domain)
        return {"title": "WHOIS Домена", "status": "error", "fields": [{"label": "Ошибка", "value": "Не удалось получить WHOIS"}]}