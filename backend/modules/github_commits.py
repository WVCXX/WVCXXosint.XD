import os
import re
import httpx
async def check_github_commits(username: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", username):
        return {
            "title": "Email в GitHub-коммитах",
            "status": "info",
            "fields": [{"label": "Статус", "value": "Некорректное имя пользователя GitHub"}],
        }
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(
                "https://api.github.com/search/commits",
                params={"q": f"author:{username}", "per_page": 100},
                headers=headers,
            )
            if response.status_code == 403:
                return {
                    "title": "Email в GitHub-коммитах",
                    "status": "info",
                    "fields": [{"label": "Статус", "value": "GitHub ограничил частоту запросов"}],
                }
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                return {
                    "title": "Email в GitHub-коммитах",
                    "status": "error",
                    "fields": [{"label": "Ошибка", "value": "GitHub API вернул некорректный ответ"}],
                }
            emails = set()
            for item in payload["items"]:
                if not isinstance(item, dict):
                    continue
                commit = item.get("commit") or {}
                author = commit.get("author") or {}
                email = author.get("email")
                if isinstance(email, str) and "@" in email:
                    emails.add(email)
            confirmed_emails = set()
            for email in sorted(emails)[:3]:
                verification = await client.get(
                    "https://api.github.com/search/commits",
                    params={"q": f"author-email:{email}", "per_page": 1},
                    headers=headers,
                )
                if verification.status_code == 403:
                    return {
                        "title": "Email в GitHub-коммитах",
                        "status": "info",
                        "fields": [{"label": "Статус", "value": "GitHub ограничил частоту запросов"}],
                    }
                verification.raise_for_status()
                verification_payload = verification.json()
                if not isinstance(verification_payload, dict):
                    continue
                for item in verification_payload.get("items", []):
                    if not isinstance(item, dict):
                        continue
                    commit = item.get("commit") or {}
                    author = commit.get("author") or {}
                    if author.get("email") == email:
                        confirmed_emails.add(email)
    except httpx.HTTPError:
        return {
            "title": "Email в GitHub-коммитах",
            "status": "error",
            "fields": [{"label": "Ошибка", "value": "GitHub API временно недоступен"}],
        }
    except ValueError:
        return {
            "title": "Email в GitHub-коммитах",
            "status": "error",
            "fields": [{"label": "Ошибка", "value": "GitHub API вернул некорректный ответ"}],
        }
    if not confirmed_emails:
        return {
            "title": "Email в GitHub-коммитах",
            "status": "info",
            "fields": [{"label": "Статус", "value": "Публичные email в найденных коммитах не обнаружены"}],
        }
    return {
        "title": "Email в GitHub-коммитах",
        "status": "ok",
        "fields": [
            {"label": "Публичных email", "value": str(len(confirmed_emails))},
            {"label": "Адреса", "value": ", ".join(sorted(confirmed_emails))},
        ],
    }
