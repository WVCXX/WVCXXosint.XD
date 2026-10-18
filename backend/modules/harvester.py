import asyncio
import re
async def run_theharvester(domain: str):
    try:
        process = await asyncio.create_subprocess_exec(
            'theHarvester', '-d', domain, '-b', 'bing', '-l', '50',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            return {
                "title": "TheHarvester (Email)",
                "status": "error",
                "fields": [{"label": "Ошибка", "value": "Не удалось запустить утилиту"}]
            }
        output = stdout.decode('utf-8', errors='ignore')
        emails = set(re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', output))
        subdomains = set(re.findall(r'([\w-]+\.' + domain.replace('.', r'\.') + r')', output))
        fields = []
        if emails:
            fields.append({"label": "Email (до 5)", "value": ", ".join(list(emails)[:5])})
        if subdomains:
            fields.append({"label": "Поддомены (до 5)", "value": ", ".join(list(subdomains)[:5])})
        if not fields:
            return {
                "title": "TheHarvester",
                "status": "info",
                "fields": [{"label": "Статус", "value": "Ничего не найдено"}]
            }
        return {
            "title": "TheHarvester",
            "status": "ok",
            "fields": fields
        }
    except Exception as e:
        return {
            "title": "TheHarvester",
            "status": "error",
            "fields": [{"label": "Ошибка", "value": str(e)}]
        }