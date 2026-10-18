from urllib.parse import quote_plus
async def check_dorking(query: str):
    dorks = {
        "PDF документы": f'"{query}" filetype:pdf',
        "Таблицы (XLS)": f'"{query}" filetype:xlsx',
        "Скрытые админки": f'site:{query} inurl:admin',
        "Открытые директории": f'site:{query} intitle:"index of"',
        "Утечки/логи": f'site:{query} (password OR passwd OR secret)'
    }
    fields = []
    for name, dork in dorks.items():
        url = f"https://www.google.com/search?q={quote_plus(dork)}"
        fields.append({"label": name, "value": url})
    return {
        "title": "Google Dorking",
        "status": "info",
        "fields": fields
    }