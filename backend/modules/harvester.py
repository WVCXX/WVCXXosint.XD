import asyncio
import re
import subprocess
async def run_theharvester(domain: str):
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            'theHarvester', '-d', domain, '-b', 'bing', '-l', '50',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=25)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return {
                "title": "TheHarvester",
                "status": "error",
                "fields": [{"label": "Ошибка", "value": "Проверка превысила лимит времени"}],
            }
        if process.returncode != 0:
            return {
                "title": "TheHarvester (Email)",
                "status": "error",
                "fields": [{"label": "Ошибка", "value": "TheHarvester завершился с ошибкой"}]
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
                "status": "no_results",
                "fields": [{"label": "Статус", "value": "Ничего не найдено"}]
            }
        return {
            "title": "TheHarvester",
            "status": "completed",
            "fields": fields
        }
    except (OSError, subprocess.SubprocessError):
        return {
            "title": "TheHarvester",
            "status": "not_configured" if process is None else "error",
            "fields": [{"label": "Ошибка", "value": "TheHarvester недоступен или не удалось запустить проверку"}]
        }