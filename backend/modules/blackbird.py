async def check_blackbird(query: str) -> dict:
    return {
        "title": "Blackbird",
        "status": "not_configured",
        "fields": [
            {
                "label": "Статус",
                "value": "Адаптер Blackbird не установлен и не запускался",
            }
        ],
    }
