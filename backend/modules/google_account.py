async def check_google_account(email: str) -> dict:
    domain = email.rsplit("@", 1)[-1].strip().rstrip(".").lower()
    if domain not in {"gmail.com", "googlemail.com"}:
        return {
            "title": "Google аккаунт",
            "status": "info",
            "fields": [{"label": "Статус", "value": "Домен не относится к Gmail/Googlemail"}],
        }
    return {
        "title": "Google аккаунт",
        "status": "info",
        "fields": [
            {
                "label": "Статус",
                "value": "Google аккаунт найден по домену; существование почтового ящика не подтверждено",
            },
            {"label": "Тип профиля", "value": "Gmail"},
            {"label": "Сервисы", "value": "Gmail, Drive, Docs"},
        ],
    }
