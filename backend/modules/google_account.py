async def check_google_account(email: str) -> dict:
    return {
        "title": "Google public metadata",
        "status": "not_configured",
        "fields": [
            {
                "label": "Статус",
                "value": "Совместимый авторизованный адаптер не подключён; наличие аккаунта не предполагается",
            }
        ],
    }
