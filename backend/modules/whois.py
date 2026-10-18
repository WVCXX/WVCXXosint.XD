import whois
async def check_whois(domain: str):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        return {
            "title": "WHOIS Домена",
            "status": "ok",
            "fields": [
                {"label": "Регистратор", "value": str(w.registrar or "Неизвестно")},
                {"label": "Дата создания", "value": str(creation or "Неизвестно")},
                {"label": "Страна", "value": str(w.country or "Неизвестно")}
            ]
        }
    except Exception:
        return {"title": "WHOIS Домена", "status": "error", "fields": [{"label": "Ошибка", "value": "Не удалось получить WHOIS"}]}