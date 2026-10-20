from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from collections.abc import Awaitable
from typing import Any
import dns.asyncresolver
import httpx
import hashlib
import asyncio
import logging
import re
from urllib.parse import quote
from bs4 import BeautifulSoup

if __package__:
    from .modules.blackbird import check_blackbird
    from .modules.config import HIBP_API_KEY
    from .modules.dorking import check_dorking
    from .modules.email_infrastructure import check_email_infrastructure
    from .modules.github_commits import check_github_commits
    from .modules.google_account import check_google_account
    from .modules.harvester import run_theharvester
    from .modules.phone import check_phone
    from .modules.public_host import (
        PublicHostError,
        normalize_public_hostname,
        resolve_public_addresses,
    )
    from .modules.shodan import check_shodan
    from .modules.whois import check_whois
else:
    from modules.blackbird import check_blackbird
    from modules.config import HIBP_API_KEY
    from modules.dorking import check_dorking
    from modules.email_infrastructure import check_email_infrastructure
    from modules.github_commits import check_github_commits
    from modules.google_account import check_google_account
    from modules.harvester import run_theharvester
    from modules.phone import check_phone
    from modules.public_host import (
        PublicHostError,
        normalize_public_hostname,
        resolve_public_addresses,
    )
    from modules.shodan import check_shodan
    from modules.whois import check_whois

logger = logging.getLogger(__name__)
app = FastAPI()
FRONTEND_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)
async def check_hibp(email: str):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}?truncateResponse=false"
    headers = {"User-Agent": "OSINT-Spider-MVP"}
    if HIBP_API_KEY:
        headers["hibp-api-key"] = HIBP_API_KEY
    async with httpx.AsyncClient() as client:
        try:
            res = await client.get(url, headers=headers, timeout=5.0)
            if res.status_code == 200:
                breaches = res.json()
                names = ", ".join([b['Name'] for b in breaches[:3]])
                if len(breaches) > 3: names += "..."
                return {"title": "Утечки (HIBP)", "status": "error", "fields": [{"label": "Найдено", "value": f"{len(breaches)} утечек"}, {"label": "Источники", "value": names}]}
            elif res.status_code == 404:
                return {"title": "Утечки (HIBP)", "status": "ok", "fields": [{"label": "Статус", "value": "Не найден в утечках"}]}
            return {"title": "Утечки (HIBP)", "status": "info", "fields": [{"label": "Статус", "value": "API ограничило запрос"}]}
        except Exception:
            return {"title": "Утечки (HIBP)", "status": "info", "fields": [{"label": "Ошибка", "value": "Сервис недоступен"}]}
async def check_pgp(email: str):
    url = f"https://keys.openpgp.org/vks/v1/by-email/{quote(email, safe='')}"
    async with httpx.AsyncClient() as client:
        try:
            res = await client.get(url, timeout=5.0)
            if res.status_code == 200:
                return {"title": "PGP Ключ", "status": "ok", "fields": [{"label": "Статус", "value": "Ключ найден"}]}
            return {"title": "PGP Ключ", "status": "info", "fields": [{"label": "Статус", "value": "Ключ не найден"}]}
        except Exception:
            return {"title": "PGP Ключ", "status": "error", "fields": [{"label": "Ошибка", "value": "Сервер недоступен"}]}
async def check_username(username: str):
    username_path = quote(username, safe="")
    sites = {
        "GitHub": f"https://github.com/{username_path}",
        "Reddit": f"https://www.reddit.com/user/{username_path}",
        "Pinterest": f"https://www.pinterest.com/{username_path}/",
        "Telegram": f"https://t.me/{username_path}"
    }
    found = []
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
        tasks = []
        for name, url in sites.items():
            tasks.append(client.get(url, headers={"User-Agent": "Mozilla/5.0"}))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for (name, url), response in zip(sites.items(), responses):
            if not isinstance(response, Exception) and response.status_code == 200:
                if "not found" not in response.text.lower() and "page not found" not in response.text.lower():
                    found.append({"site": name, "url": url})
    if found:
        fields = [{"label": f"{f['site']}", "value": f["url"]} for f in found]
        return {"title": f"Профили ({len(found)})", "status": "ok", "fields": fields}
    else:
        return {"title": "Профили", "status": "info", "fields": [{"label": "Статус", "value": "Не найден"}]}
async def get_domain_nodes(domain: str):
    try:
        domain = normalize_public_hostname(domain)
    except PublicHostError as error:
        return [{
            "title": "Веб-сайт",
            "status": "error",
            "fields": [{"label": "Ошибка", "value": str(error)}],
        }]

    try:
        public_ips = await resolve_public_addresses(domain)
    except PublicHostError as error:
        logger.info("Skipping domain web check for %s: %s", domain, error)
        public_ips = []

    async def dns_mx():
        try:
            records = await dns.asyncresolver.resolve(domain, 'MX')
            mx = ", ".join([str(r.exchange) for r in records])
            return {"title": "MX Записи", "status": "ok", "fields": [{"label": "Сервера", "value": mx[:40] + "..."}]}
        except Exception:
            return {"title": "MX Записи", "status": "error", "fields": [{"label": "Ошибка", "value": "Не найдены"}]}
    async def dns_ip():
        if not public_ips:
            return [{"title": "IP Адрес", "status": "error", "fields": [{"label": "Ошибка", "value": "Публичный IP не найден"}]}]
        res = {"title": "IP Адрес", "status": "ok", "fields": [{"label": "IP", "value": ", ".join(public_ips)}]}
        shodan_res = await check_shodan(public_ips[0])
        return [res, shodan_res]
    async def web_title():
        if not public_ips:
            return {"title": "Веб-сайт", "status": "error", "fields": [{"label": "Ошибка", "value": "Запрос отменён: нет подтверждённого публичного IP"}]}

        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=10.0,
            trust_env=False,
        ) as client:
            for ip in public_ips:
                address = f"[{ip}]" if ":" in ip else ip
                try:
                    res = await client.get(
                        f"https://{address}/",
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            "Host": domain,
                        },
                        extensions={"sni_hostname": domain.encode("ascii")},
                    )
                    soup = BeautifulSoup(res.text, 'html.parser')
                    title = soup.title.string.strip() if soup.title else "Нет заголовка"
                    return {"title": "Веб-сайт", "status": "ok", "fields": [{"label": "HTTP", "value": str(res.status_code)}, {"label": "Title", "value": title}]}
                except httpx.HTTPError:
                    continue
        return {"title": "Веб-сайт", "status": "error", "fields": [{"label": "Ошибка", "value": "Сайт недоступен"}]}
    tasks = [dns_mx(), dns_ip(), web_title(), run_theharvester(domain), check_whois(domain), check_dorking(domain)]
    results = await asyncio.gather(*tasks)
    nodes = []
    for res in results:
        if isinstance(res, list):
            nodes.extend(res)
        else:
            nodes.append(res)
    return nodes
async def _gravatar_result(email: str) -> dict:
    email_hash = hashlib.md5(email.lower().encode(), usedforsecurity=False).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            response = await client.get(gravatar_url)
            if response.status_code == 200:
                return {
                    "title": "Gravatar",
                    "status": "ok",
                    "fields": [
                        {"label": "Статус", "value": "Найден"},
                        {"label": "Ссылка", "value": gravatar_url},
                    ],
                }
            return {
                "title": "Gravatar",
                "status": "info",
                "fields": [{"label": "Статус", "value": "Не установлен"}],
            }
        except httpx.HTTPError:
            return {
                "title": "Gravatar",
                "status": "error",
                "fields": [{"label": "Ошибка", "value": "Сбой связи"}],
            }
async def _stream_checks(
    websocket: WebSocket,
    checks: list[tuple[str, Awaitable[Any]]],
) -> None:
    ready: asyncio.Queue[Any] = asyncio.Queue()

    async def run_check(title: str, check: Awaitable[Any]) -> None:
        try:
            result = await check
        except Exception:
            logger.exception("OSINT check failed: %s", title)
            result = {
                "title": title,
                "status": "error",
                "fields": [{"label": "Ошибка", "value": "Проверка временно недоступна"}],
            }
        await ready.put(result)

    jobs = asyncio.gather(
        *(run_check(title, check) for title, check in checks)
    )
    try:
        for _ in checks:
            result = await ready.get()
            results = result if isinstance(result, list) else [result]
            for node in results:
                await websocket.send_json({"type": "node", "data": node})
        await jobs
    finally:
        if not jobs.done():
            jobs.cancel()
            try:
                await jobs
            except asyncio.CancelledError:
                pass
@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    origin = websocket.headers.get("origin")
    if origin is not None and origin not in FRONTEND_ORIGINS:
        await websocket.close(code=1008, reason="Origin not allowed")
        return
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        query = data.get("query", "").strip() if isinstance(data, dict) else ""
        if not query:
            await websocket.send_json({"error": "Пустой запрос"})
            return
        is_phone = (
            bool(re.fullmatch(r"\+?[0-9\s().-]+", query))
            and 10 <= len(re.sub(r"[^0-9]", "", query)) <= 15
        )
        is_email = query.count("@") == 1 and "." in query.rsplit("@", 1)[1]
        is_domain = "." in query and " " not in query and not is_phone
        if is_email:
            username, domain = query.split("@", 1)
            input_type = "email"
        elif is_domain:
            input_type = "domain"
        elif is_phone:
            input_type = "phone"
        else:
            input_type = "username"
        await websocket.send_json(
            {"type": "root", "data": {"query": query, "input_type": input_type}}
        )
        if input_type == "email":
            checks = [
                ("SMTP & Домен", check_email_infrastructure(query)),
                ("Blackbird (демо)", check_blackbird(query)),
                ("Google аккаунт", check_google_account(query)),
                ("Email в GitHub-коммитах", check_github_commits(username)),
                ("Утечки (HIBP)", check_hibp(query)),
                ("PGP Ключ", check_pgp(query)),
                ("Gravatar", _gravatar_result(query)),
                ("Информация о домене", get_domain_nodes(domain)),
            ]
            await _stream_checks(websocket, checks)
        elif input_type == "domain":
            await _stream_checks(
                websocket, [("Информация о домене", get_domain_nodes(query))]
            )
        elif input_type == "phone":
            await _stream_checks(websocket, [("Телефон", check_phone(query))])
        else:
            await _stream_checks(
                websocket,
                [
                    ("Профили", check_username(query)),
                    ("Google Dorking", check_dorking(query)),
                    ("Email в GitHub-коммитах", check_github_commits(query)),
                ],
            )
        await websocket.send_json({"type": "done"})
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected during scan")
    except Exception:
        logger.exception("WebSocket scan failed")
        try:
            await websocket.send_json(
                {"error": "Сканирование не удалось завершить. Попробуйте ещё раз."}
            )
        except (WebSocketDisconnect, RuntimeError):
            pass
    finally:
        try:
            await websocket.close()
        except (WebSocketDisconnect, RuntimeError):
            pass