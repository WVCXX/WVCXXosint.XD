async def check_blackbird(email: str) -> dict:
    if email.count("@") != 1:
        return {
            "title": "Blackbird (демо)",
            "status": "error",
            "fields": [{"label": "Ошибка", "value": "Некорректный email"}],
        }
    return {
        "title": "Blackbird (демо)",
        "status": "info",
        "fields": [
            {"label": "Режим", "value": "Демонстрационные ссылки; регистрация email не проверялась"},
            {"label": "Chess.com", "value": "https://www.chess.com/"},
            {"label": "Spotify", "value": "https://www.spotify.com/"},
            {"label": "X (Twitter)", "value": "https://x.com/"},
        ],
    }
