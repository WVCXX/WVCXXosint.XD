async def check_dorking(query: str) -> dict:
    return {
        "title": "Public search",
        "status": "not_configured",
        "fields": [
            {
                "label": "Статус",
                "value": "Поисковый API не подключён; поиск не выполнялся",
            }
        ],
    }
