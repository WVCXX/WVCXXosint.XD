import re
from urllib.parse import quote_plus

import httpx

from .config import get_api_key


async def check_github_commits(query: str) -> dict:
    is_email = "@" in query
    if is_email:
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", query):
            return {
                "title": "Email в GitHub-коммитах",
                "status": "error",
                "fields": [{"label": "Ошибка", "value": "Некорректный email"}],
            }
        search_query = f"author-email:{query}"
    else:
        if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", query):
            return {
                "title": "Email в GitHub-коммитах",
                "status": "error",
                "fields": [{"label": "Ошибка", "value": "Некорректное имя пользователя GitHub"}],
            }
        search_query = f"author:{query}"

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    github_token = get_api_key("github")
    if github_token:
        headers["Authorization"] = "Bearer " + github_token

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(
                "https://api.github.com/search/commits",
                params={"q": search_query, "per_page": 100},
                headers=headers,
            )
            if response.status_code in (403, 429):
                return {
                    "title": "Email в GitHub-коммитах",
                    "status": "rate_limited",
                    "fields": [{"label": "Статус", "value": "GitHub ограничил частоту запросов"}],
                }
            response.raise_for_status()
            payload = response.json()
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

    items = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        return {
            "title": "Email в GitHub-коммитах",
            "status": "error",
            "fields": [{"label": "Ошибка", "value": "GitHub API вернул некорректный ответ"}],
        }

    emails = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        commit = item.get("commit") or {}
        if not isinstance(commit, dict):
            continue
        author = commit.get("author") or {}
        if not isinstance(author, dict):
            continue
        email = author.get("email")
        if isinstance(email, str) and "@" in email and (not is_email or email.lower() == query.lower()):
            emails.add(email)

    if not emails:
        return {
            "title": "Email в GitHub-коммитах",
            "status": "no_results",
            "fields": [{"label": "Статус", "value": "Совпадений в публичных коммитах не обнаружено"}],
        }

    return {
        "title": "Email в GitHub-коммитах",
        "status": "completed",
        "source_url": "https://github.com/search?q=" + quote_plus(search_query),
        "fields": [
            {"label": "Публичных email", "value": str(len(emails))},
            {"label": "Адреса", "value": ", ".join(sorted(emails))},
        ],
    }
