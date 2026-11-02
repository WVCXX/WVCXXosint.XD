from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from collections.abc import Awaitable
from typing import Any, Protocol
from pydantic import BaseModel
from datetime import datetime, timezone
from pathlib import Path
import ipaddress
import json
import sqlite3
import uuid
import time
from contextlib import asynccontextmanager
import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
import hashlib
import asyncio
import logging
import re
from urllib.parse import quote, quote_plus, urljoin, urlsplit
from bs4 import BeautifulSoup

if __package__:
    from .modules.config import API_KEY_ENV, clear_api_key, get_api_key, get_api_key_statuses, set_api_key
    from .modules.email_infrastructure import check_email_infrastructure
    from .modules.exiftool import read_metadata
    from .modules.github_commits import check_github_commits
    from .modules.harvester import run_theharvester
    from .modules.phone import check_phone
    from .modules.public_host import (
        PublicHostError,
        normalize_public_hostname,
        resolve_public_addresses,
    )
    from .modules.shodan import check_shodan
    from .modules.whatsmyname import check_whatsmyname
    from .modules.whois import check_whois
    from .modules.registry import get_tools
else:
    from modules.config import API_KEY_ENV, clear_api_key, get_api_key, get_api_key_statuses, set_api_key
    from modules.email_infrastructure import check_email_infrastructure
    from modules.exiftool import read_metadata
    from modules.github_commits import check_github_commits
    from modules.harvester import run_theharvester
    from modules.phone import check_phone
    from modules.public_host import (
        PublicHostError,
        normalize_public_hostname,
        resolve_public_addresses,
    )
    from modules.shodan import check_shodan
    from modules.whatsmyname import check_whatsmyname
    from modules.whois import check_whois
    from modules.registry import get_tools

logger = logging.getLogger(__name__)

# Категории проверок (ключ → отображение на фронте в i18n) и эвристика доверия источникам.
CONFIDENCE_BY_TITLE = {
    "SMTP & Домен": "high",
    "MX Записи": "high",
    "DNS Записи": "high",
    "IP Адрес": "high",
    "RDAP / IP": "high",
    "WHOIS Домена": "high",
    "Certificate Transparency": "high",
    "Internet Archive": "high",
    "Shodan (Порты)": "high",
    "Утечки (HIBP)": "high",
    "PGP Ключ": "high",
    "GitHub profile": "high",
    "Организация GitHub": "high",
    "Информация о телефоне": "medium",
    "Веб-сайт": "medium",
    "Gravatar": "medium",
    "Организации (Wikidata)": "medium",
    "TheHarvester": "low",
    "Email в GitHub-коммитах": "low",
    "Профили (WhatsMyName)": "low",
}


class JSONSocket(Protocol):
    async def send_json(self, data: Any) -> None: ...


@asynccontextmanager
async def lifespan(_: FastAPI):
    monitor_task = asyncio.create_task(_monitor_loop())
    try:
        yield
    finally:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass


app = FastAPI(lifespan=lifespan)
FRONTEND_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


class APIKeyPayload(BaseModel):
    value: str


def _require_local_settings_access(request: Request) -> None:
    client = request.client
    origin = request.headers.get("origin")
    try:
        is_local = client is not None and ipaddress.ip_address(client.host).is_loopback
    except ValueError:
        is_local = False
    if not is_local or (origin is not None and origin not in FRONTEND_ORIGINS):
        raise HTTPException(status_code=403, detail="Settings can only be changed locally")


@app.get("/api/tools")
async def tools_catalog():
    return {"tools": get_tools()}


@app.get("/api/health")
async def backend_health():
    tools = get_tools()
    return {
        "status": "ok",
        "module_count": len(tools),
        "available_count": sum(tool["status"] == "available" for tool in tools),
    }


@app.get("/api/settings/keys")
async def api_key_settings(request: Request):
    _require_local_settings_access(request)
    return {"keys": get_api_key_statuses()}


@app.put("/api/settings/keys/{provider}")
async def update_api_key(provider: str, payload: APIKeyPayload, request: Request):
    _require_local_settings_access(request)
    if provider not in API_KEY_ENV:
        raise HTTPException(status_code=404, detail="Unknown API key provider")
    try:
        set_api_key(provider, payload.value)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return {"keys": get_api_key_statuses()}


@app.delete("/api/settings/keys/{provider}")
async def remove_api_key(provider: str, request: Request):
    _require_local_settings_access(request)
    if provider not in API_KEY_ENV:
        raise HTTPException(status_code=404, detail="Unknown API key provider")
    clear_api_key(provider)
    return {"keys": get_api_key_statuses()}


@app.post("/api/exif")
async def exif_upload(request: Request):
    content = await request.body()
    if not content or len(content) > 25 * 1024 * 1024:
        return {"title": "ExifTool", "status": "error", "fields": [{"label": "Ошибка", "value": "Файл отсутствует или превышает 25 МБ"}]}
    filename = request.headers.get("x-file-name", "upload.bin")[:255]
    return await read_metadata(filename, content)


async def check_hibp(email: str):
    api_key = get_api_key("hibp")
    if not api_key:
        return {
            "title": "Утечки (HIBP)",
            "status": "not_configured",
            "fields": [{"label": "Статус", "value": "Добавьте API-ключ HIBP в Настройках приложения"}],
        }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}?truncateResponse=false"
    headers = {"User-Agent": "OSINT-Spider-MVP"}
    headers["hibp-api-key"] = api_key
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, trust_env=False) as client:
        try:
            res = await client.get(url, headers=headers)
            if res.status_code == 200:
                breaches = res.json()
                if not isinstance(breaches, list):
                    raise ValueError("Unexpected HIBP response")
                names = ", ".join(str(b.get("Name", "")) for b in breaches[:5] if isinstance(b, dict))
                return {
                    "title": "Утечки (HIBP)",
                    "status": "completed",
                    "source_url": "https://haveibeenpwned.com/",
                    "fields": [
                        {"label": "Найдено инцидентов", "value": str(len(breaches))},
                        {"label": "Источники", "value": names or "Не указаны"},
                    ],
                }
            if res.status_code == 404:
                return {"title": "Утечки (HIBP)", "status": "no_results", "fields": [{"label": "Статус", "value": "Инциденты не обнаружены в HIBP; это не доказывает их отсутствие в других источниках"}]}
            if res.status_code == 429:
                return {"title": "Утечки (HIBP)", "status": "rate_limited", "fields": [{"label": "Статус", "value": "HIBP ограничил частоту запросов"}]}
            return {"title": "Утечки (HIBP)", "status": "error", "fields": [{"label": "Статус", "value": f"HIBP вернул HTTP {res.status_code}"}]}
        except (httpx.HTTPError, ValueError):
            logger.exception("HIBP request failed")
            return {"title": "Утечки (HIBP)", "status": "error", "fields": [{"label": "Ошибка", "value": "Сервис временно недоступен или вернул некорректный ответ"}]}


async def check_pgp(email: str):
    url = f"https://keys.openpgp.org/vks/v1/by-email/{quote(email, safe='')}"
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, trust_env=False) as client:
        try:
            res = await client.get(url)
            if res.status_code == 200:
                return {"title": "PGP Ключ", "status": "completed", "source_url": url, "fields": [{"label": "Статус", "value": "Публичный ключ найден"}]}
            if res.status_code == 404:
                return {"title": "PGP Ключ", "status": "no_results", "fields": [{"label": "Статус", "value": "Публичный ключ не опубликован в этом каталоге"}]}
            if res.status_code == 429:
                return {"title": "PGP Ключ", "status": "rate_limited", "fields": [{"label": "Статус", "value": "Сервис ограничил частоту запросов"}]}
            return {"title": "PGP Ключ", "status": "error", "fields": [{"label": "Статус", "value": f"Сервис вернул HTTP {res.status_code}"}]}
        except httpx.HTTPError:
            return {"title": "PGP Ключ", "status": "error", "fields": [{"label": "Ошибка", "value": "Сервер недоступен"}]}


async def check_username(username: str):
    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", username):
        return {"title": "GitHub profile", "status": "error", "fields": [{"label": "Ошибка", "value": "Некорректное имя пользователя"}]}
    url = f"https://api.github.com/users/{quote(username, safe='')}"
    headers = {"Accept": "application/vnd.github+json"}
    github_token = get_api_key("github")
    if github_token:
        headers["Authorization"] = "Bearer " + github_token
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, trust_env=False) as client:
            response = await client.get(url, headers=headers)
        if response.status_code == 200:
            profile = response.json()
            if not isinstance(profile, dict):
                raise ValueError("Unexpected GitHub profile response")
            return {
                "title": "GitHub profile",
                "status": "completed",
                "source_url": profile.get("html_url", f"https://github.com/{quote(username, safe='')}"),
                "fields": [
                    {"label": "Профиль", "value": profile.get("html_url", "")},
                    {"label": "Имя", "value": profile.get("name") or "Не указано"},
                    {"label": "Публичных репозиториев", "value": str(profile.get("public_repos", 0))},
                ],
            }
        if response.status_code == 404:
            return {"title": "GitHub profile", "status": "no_results", "fields": [{"label": "Статус", "value": "Публичный профиль GitHub не найден; другие сервисы не проверялись"}]}
        if response.status_code in (403, 429):
            return {"title": "GitHub profile", "status": "rate_limited", "fields": [{"label": "Статус", "value": "GitHub ограничил частоту запросов"}]}
        return {"title": "GitHub profile", "status": "error", "fields": [{"label": "Статус", "value": f"GitHub API вернул HTTP {response.status_code}"}]}
    except (httpx.HTTPError, ValueError):
        return {"title": "GitHub profile", "status": "error", "fields": [{"label": "Ошибка", "value": "GitHub API временно недоступен"}]}


async def check_github_organization(name: str) -> dict:
    title = "Организация GitHub"
    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", name):
        return {"title": title, "status": "error", "fields": [{"label": "Ошибка", "value": "Некорректный логин организации"}]}
    url = f"https://api.github.com/orgs/{quote(name, safe='')}"
    headers = {"Accept": "application/vnd.github+json"}
    github_token = get_api_key("github")
    if github_token:
        headers["Authorization"] = "Bearer " + github_token
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, trust_env=False) as client:
            response = await client.get(url, headers=headers)
        if response.status_code == 200:
            org = response.json()
            if not isinstance(org, dict):
                raise ValueError("Unexpected GitHub organization response")
            login = str(org.get("login") or name)
            return {
                "title": title,
                "status": "completed",
                "source_url": f"https://github.com/{login}",
                "fields": [
                    {"label": "Логин", "value": login},
                    {"label": "Название", "value": str(org.get("name") or "Не указано")},
                    {"label": "Блог", "value": str(org.get("blog") or "Не указан")},
                    {"label": "Публичных репозиториев", "value": str(org.get("public_repos", 0))},
                ],
            }
        if response.status_code == 404:
            return {"title": title, "status": "no_results", "fields": [{"label": "Статус", "value": "Публичная организация GitHub не найдена"}]}
        if response.status_code in (403, 429):
            return {"title": title, "status": "rate_limited", "fields": [{"label": "Статус", "value": "GitHub ограничил частоту запросов"}]}
        return {"title": title, "status": "error", "fields": [{"label": "Статус", "value": f"GitHub API вернул HTTP {response.status_code}"}]}
    except (httpx.HTTPError, ValueError):
        return {"title": title, "status": "error", "fields": [{"label": "Ошибка", "value": "GitHub API временно недоступен"}]}


async def check_wikidata_organization(query: str) -> dict:
    title = "Организации (Wikidata)"
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, trust_env=False) as client:
            response = await client.get(
                "https://www.wikidata.org/w/api.php",
                params={
                    "action": "wbsearchentities",
                    "search": query,
                    "language": "ru",
                    "uselang": "ru",
                    "type": "item",
                    "format": "json",
                    "limit": 5,
                },
            )
        if response.status_code != 200:
            return {"title": title, "status": "error", "source_url": "https://www.wikidata.org/", "fields": [{"label": "Ошибка", "value": f"Wikidata вернул HTTP {response.status_code}"}]}
        payload = response.json()
        entities = payload.get("search") if isinstance(payload, dict) else None
        if not isinstance(entities, list):
            raise ValueError("Unexpected Wikidata response")
        matches = []
        for entity in entities[:5]:
            if not isinstance(entity, dict):
                continue
            label = str(entity.get("label") or "")
            description = str(entity.get("description") or "")
            entity_id = str(entity.get("id") or "")
            if not entity_id:
                continue
            matches.append({
                "label": label or entity_id,
                "description": description[:160] or "Без описания",
                "url": f"https://www.wikidata.org/wiki/{entity_id}",
            })
        if not matches:
            return {"title": title, "status": "no_results", "source_url": "https://www.wikidata.org/", "fields": [{"label": "Статус", "value": "Сущности с таким названием не найдены"}]}
        fields = [{"label": "Найдено сущностей", "value": str(len(matches))}]
        fields.extend({"label": item["label"], "value": item["description"]} for item in matches)
        return {
            "title": title,
            "status": "completed",
            "source_url": "https://www.wikidata.org/",
            "fields": fields,
            "links": [item["url"] for item in matches],
        }
    except (httpx.HTTPError, ValueError):
        logger.exception("Wikidata organization lookup failed for %s", query)
        return {"title": title, "status": "error", "source_url": "https://www.wikidata.org/", "fields": [{"label": "Ошибка", "value": "Wikidata временно недоступен"}]}


async def check_certificate_transparency(domain: str, depth: int) -> dict:
    source = "https://crt.sh/?q=" + quote_plus("%." + domain)
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=False, trust_env=False) as client:
            response = await client.get("https://crt.sh/", params={"q": "%." + domain, "output": "json"})
        if response.status_code != 200:
            return {"title": "Certificate Transparency", "status": "error", "source_url": source, "fields": [{"label": "Ошибка", "value": f"crt.sh вернул HTTP {response.status_code}"}]}
        payload = response.json()
        if not isinstance(payload, list):
            raise ValueError("Unexpected crt.sh response")
        hostnames = set()
        suffix = "." + domain
        for record in payload:
            if not isinstance(record, dict):
                continue
            for name in str(record.get("name_value", "")).splitlines():
                candidate = name.strip().lower().removeprefix("*.")
                if candidate.endswith(suffix) and candidate != domain:
                    extra_labels = candidate[: -len(suffix)].count(".") + 1
                    if extra_labels <= depth:
                        hostnames.add(candidate)
        names = sorted(hostnames)[:50]
        if not names:
            return {"title": "Certificate Transparency", "status": "no_results", "source_url": source, "fields": [{"label": "Статус", "value": "Поддомены в ответе crt.sh не обнаружены"}]}
        return {"title": "Certificate Transparency", "status": "completed", "source_url": source, "fields": [{"label": "Поддомены из сертификатов", "value": ", ".join(names)}]}
    except (httpx.HTTPError, ValueError):
        logger.exception("Certificate Transparency lookup failed for %s", domain)
        return {"title": "Certificate Transparency", "status": "error", "source_url": source, "fields": [{"label": "Ошибка", "value": "Не удалось получить или разобрать ответ crt.sh"}]}


async def check_dns_records(domain: str) -> dict:
    async def safe_resolve(name: str, record_type: str) -> tuple[str, list]:
        try:
            records = await dns.asyncresolver.resolve(name, record_type)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return ("empty", [])
        except dns.exception.DNSException:
            return ("error", [])
        return ("ok", list(records))

    def txt_value(record) -> str:
        strings = getattr(record, "strings", None)
        if strings:
            return b"".join(strings).decode("utf-8", errors="replace")
        return str(record).strip('"')

    ns_result, root_result, dmarc_result = await asyncio.gather(
        safe_resolve(domain, "NS"),
        safe_resolve(domain, "TXT"),
        safe_resolve(f"_dmarc.{domain}", "TXT"),
    )
    ns_nameservers, ns_records = ns_result
    _, root_records = root_result
    _, dmarc_records = dmarc_result
    name_servers = sorted(str(record).rstrip(".") for record in ns_records)
    txt_values = [txt_value(record) for record in root_records]
    dmarc_values = [txt_value(record) for record in dmarc_records]
    statuses = [state for state, _ in (ns_result, root_result, dmarc_result)]
    if all(state == "error" for state in statuses):
        return {"title": "DNS Записи", "status": "error", "fields": [{"label": "Ошибка", "value": "Не удалось выполнить DNS-запрос"}]}
    spf_status = next(
        (value for value in txt_values if value.lower().startswith("v=spf1")),
        None,
    )
    dmarc_status = next(
        (value for value in dmarc_values if value.lower().startswith("v=dmarc1")),
        None,
    )
    if not name_servers and spf_status is None and dmarc_status is None:
        return {"title": "DNS Записи", "status": "no_results", "fields": [{"label": "Статус", "value": "NS, SPF и DMARC записи не найдены"}]}
    fields = [{"label": "NS сервера", "value": ", ".join(name_servers[:8]) or "Не найдены"}]
    fields.append({"label": "SPF", "value": (spf_status[:200] if spf_status else "Не настроен")})
    fields.append({"label": "DMARC", "value": (dmarc_status[:200] if dmarc_status else "Не настроен")})
    return {"title": "DNS Записи", "status": "completed", "fields": fields}


async def check_wayback(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, trust_env=False) as client:
            response = await client.get("https://archive.org/wayback/available", params={"url": domain})
        if response.status_code != 200:
            return {"title": "Internet Archive", "status": "error", "source_url": "https://web.archive.org/", "fields": [{"label": "Ошибка", "value": f"Wayback API вернул HTTP {response.status_code}"}]}
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Unexpected Wayback response")
        archived = payload.get("archived_snapshots")
        snapshot = archived.get("closest") if isinstance(archived, dict) else None
        snapshot_url = snapshot.get("url") if isinstance(snapshot, dict) else None
        if snapshot.get("available") and isinstance(snapshot_url, str) and "://web.archive.org/web/" in snapshot_url:
            # Нормализуем схему URL-а снимка: API может вернуть http://.
            snapshot_url = "https://web.archive.org/web/" + snapshot_url.split("://web.archive.org/web/", 1)[1]
            timestamp = str(snapshot.get("timestamp", ""))
            readable = (
                timestamp[0:4] + "-" + timestamp[4:6] + "-" + timestamp[6:8]
                if len(timestamp) >= 8 and timestamp.isdigit()
                else timestamp or "Неизвестно"
            )
            return {
                "title": "Internet Archive",
                "status": "completed",
                "source_url": snapshot_url,
                "fields": [
                    {"label": "Ближайший снимок", "value": readable},
                    {"label": "Ссылка", "value": snapshot_url},
                ],
            }
        return {"title": "Internet Archive", "status": "no_results", "source_url": "https://web.archive.org/", "fields": [{"label": "Статус", "value": "Снимки для этого домена не найдены"}]}
    except (httpx.HTTPError, ValueError):
        logger.exception("Wayback lookup failed for %s", domain)
        return {"title": "Internet Archive", "status": "error", "source_url": "https://web.archive.org/", "fields": [{"label": "Ошибка", "value": "Не удалось получить ответ Internet Archive"}]}


async def get_ip_nodes(ip: str) -> list[dict]:
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        return [{"title": "RDAP / IP", "status": "error", "fields": [{"label": "Ошибка", "value": "Разрешены только публичные IP-адреса"}]}]
    url = f"https://rdap.org/ip/{address.compressed}"
    async def lookup_rdap():
        try:
            current_url = url
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, trust_env=False) as client:
                response = None
                for _ in range(4):
                    parsed = urlsplit(current_url)
                    hostname = parsed.hostname
                    if (
                        parsed.scheme != "https"
                        or not hostname
                        or parsed.username is not None
                        or parsed.password is not None
                        or parsed.port not in (None, 443)
                    ):
                        raise PublicHostError("RDAP redirected to an unsupported destination")
                    hostname = normalize_public_hostname(hostname)
                    addresses = await resolve_public_addresses(hostname)
                    path = parsed.path or "/"
                    if parsed.query:
                        path += "?" + parsed.query
                    for resolved_ip in addresses:
                        ip_literal = f"[{resolved_ip}]" if ":" in resolved_ip else resolved_ip
                        try:
                            response = await client.get(
                                f"https://{ip_literal}{path}",
                                headers={"Accept": "application/rdap+json", "Host": hostname},
                                extensions={"sni_hostname": hostname},
                            )
                            break
                        except httpx.HTTPError:
                            response = None
                    if response is None:
                        raise httpx.ConnectError("No public RDAP address responded")
                    if response.status_code not in (301, 302, 303, 307, 308):
                        break
                    location = response.headers.get("location")
                    if not location:
                        break
                    current_url = urljoin(current_url, location)
                else:
                    raise PublicHostError("RDAP exceeded the redirect limit")
            if response is None:
                raise httpx.ConnectError("RDAP did not return a response")
            if response.status_code != 200:
                return {"title": "RDAP / IP", "status": "error", "source_url": url, "fields": [{"label": "Ошибка", "value": f"RDAP вернул HTTP {response.status_code}"}]}
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("Unexpected RDAP response")
            return {
                "title": "RDAP / IP",
                "status": "completed",
                "source_url": current_url,
                "fields": [
                    {"label": "IP", "value": address.compressed},
                    {"label": "Сеть", "value": data.get("name") or data.get("handle") or "Не указана"},
                    {"label": "Источник данных", "value": str(data.get("port43") or "RDAP registry")},
                ],
            }
        except PublicHostError:
            logger.warning("Rejected unsafe RDAP redirect for %s", address.compressed)
            return {"title": "RDAP / IP", "status": "error", "source_url": url, "fields": [{"label": "Ошибка", "value": "RDAP перенаправил запрос на неподдерживаемый или непубличный адрес"}]}
        except (httpx.HTTPError, ValueError):
            logger.exception("RDAP lookup failed for %s", address.compressed)
            return {"title": "RDAP / IP", "status": "error", "source_url": url, "fields": [{"label": "Ошибка", "value": "RDAP временно недоступен или вернул некорректный ответ"}]}
    return await asyncio.gather(lookup_rdap(), check_shodan(address.compressed))


async def get_domain_checks(domain: str, depth: int = 1) -> list[tuple[str, Awaitable[Any]]]:
    try:
        domain = normalize_public_hostname(domain)
    except PublicHostError as error:
        result = {
            "title": "Domain validation",
            "status": "error",
            "fields": [{"label": "Ошибка", "value": str(error)}],
        }
        return [("Domain validation", asyncio.sleep(0, result=result))]

    try:
        public_ips = await resolve_public_addresses(domain)
    except PublicHostError as error:
        logger.info("Skipping domain web check for %s: %s", domain, error)
        public_ips = []

    async def dns_mx():
        try:
            records = await dns.asyncresolver.resolve(domain, "MX")
            mx = ", ".join(str(record.exchange).rstrip(".") for record in records)
            return {"title": "MX Записи", "status": "completed", "fields": [{"label": "Сервера", "value": mx}]}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return {"title": "MX Записи", "status": "no_results", "fields": [{"label": "Статус", "value": "MX-записи не найдены"}]}
        except dns.exception.DNSException:
            logger.exception("MX lookup failed for %s", domain)
            return {"title": "MX Записи", "status": "error", "fields": [{"label": "Ошибка", "value": "Не удалось выполнить DNS-запрос"}]}
    async def dns_ip():
        if not public_ips:
            return {"title": "IP Адрес", "status": "no_results", "fields": [{"label": "Статус", "value": "Публичный IP не найден"}]}
        return {"title": "IP Адрес", "status": "completed", "fields": [{"label": "IP", "value": ", ".join(public_ips)}]}

    async def shodan_lookup():
        if not public_ips:
            return {"title": "Shodan", "status": "no_results", "fields": [{"label": "Статус", "value": "Проверка пропущена: публичный IP не найден"}]}
        return await check_shodan(public_ips[0])

    async def web_title():
        if not public_ips:
            return {"title": "Веб-сайт", "status": "no_results", "fields": [{"label": "Статус", "value": "Запрос не выполнялся: нет подтверждённого публичного IP"}]}

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
                        extensions={"sni_hostname": domain},
                    )
                    soup = BeautifulSoup(res.text, 'html.parser')
                    title_text = soup.title.get_text(strip=True) if soup.title else ""
                    title = title_text[:160] or "Нет заголовка"
                    return {"title": "Веб-сайт", "status": "completed", "fields": [{"label": "HTTP", "value": str(res.status_code)}, {"label": "Title", "value": title}]}
                except httpx.HTTPError:
                    continue
        return {"title": "Веб-сайт", "status": "error", "fields": [{"label": "Ошибка", "value": "Сайт недоступен"}]}
    checks = [
        ("MX records", "dns", dns_mx()),
        ("DNS records", "dns", check_dns_records(domain)),
        ("IP addresses", "dns", dns_ip()),
        ("Shodan", "reputation", shodan_lookup()),
        ("Website metadata", "web", web_title()),
        ("TheHarvester", "search", run_theharvester(domain)),
        ("WHOIS", "whois", check_whois(domain)),
        ("Internet Archive", "web", check_wayback(domain)),
    ]
    if depth > 1:
        checks.append(("Certificate Transparency", "web", check_certificate_transparency(domain, depth - 1)))
    return checks


def _category_of(check: tuple) -> str | None:
    return check[1] if len(check) >= 3 else None


def _coro_of(check: tuple):
    return check[-1]


async def get_domain_nodes(domain: str, depth: int = 1) -> list[dict]:
    checks = await get_domain_checks(domain, depth)
    return await _collect_results(checks, "")


_STATE_BY_STATUS = {
    "ok": "completed",
    "completed": "completed",
    "error": "failed",
    "no_results": "no_results",
    "partial": "partial",
    "info": "partial",
    "not_configured": "not_configured",
    "rate_limited": "rate_limited",
}

SOURCE_URLS = {
    "SMTP & Домен": "https://www.rfc-editor.org/rfc/rfc1035",
    "MX Записи": "https://www.rfc-editor.org/rfc/rfc1035",
    "DNS Записи": "https://www.rfc-editor.org/rfc/rfc1035",
    "IP Адрес": "https://www.rfc-editor.org/rfc/rfc1035",
    "Веб-сайт": "https://www.rfc-editor.org/rfc/rfc9110",
    "Информация о домене": "https://rdap.org/",
    "WHOIS Домена": "https://www.icann.org/rdap",
    "TheHarvester": "https://github.com/laramies/theHarvester",
    "TheHarvester (Email)": "https://github.com/laramies/theHarvester",
    "GitHub profile": "https://docs.github.com/en/rest/users/users",
    "Email в GitHub-коммитах": "https://docs.github.com/en/rest/search/search",
    "Утечки (HIBP)": "https://haveibeenpwned.com/API/v3",
    "PGP Ключ": "https://keys.openpgp.org/",
    "Gravatar": "https://gravatar.com/",
    "Certificate Transparency": "https://crt.sh/",
    "RDAP / IP": "https://rdap.org/",
    "Internet Archive": "https://web.archive.org/",
    "Shodan (Порты)": "https://developer.shodan.io/api",
    "Профили (WhatsMyName)": "https://github.com/WebBreacher/WhatsMyName",
    "Организация GitHub": "https://docs.github.com/en/rest/orgs/orgs",
    "Организации (Wikidata)": "https://www.wikidata.org/",
}


def _normalize_node(
    item: dict,
    title: str,
    query: str,
    check_id: str,
    category: str | None,
    index: int,
) -> dict:
    if not isinstance(item.get("fields"), list):
        item["fields"] = []
    status = item.get("status", "info")
    normalized_title = str(item.get("title") or title)
    item["id"] = str(item.get("id") or (check_id if index == 0 else uuid.uuid4()))
    item.setdefault("query", query)
    item.setdefault("tool", normalized_title)
    item.setdefault("check_title", title)
    item.setdefault("received_at", datetime.now(timezone.utc).isoformat())
    item.setdefault("entity_type", "OSINT Module")
    item["state"] = _STATE_BY_STATUS.get(status, "partial")
    item.setdefault("source_url", SOURCE_URLS.get(normalized_title))
    item["confidence"] = item.get("confidence") or CONFIDENCE_BY_TITLE.get(normalized_title) or "medium"
    item.setdefault("evidence_type", "source_response")
    item.setdefault("errors", [
        str(field.get("value", ""))
        for field in item["fields"]
        if isinstance(field, dict) and field.get("label") == "Ошибка"
    ])
    item.setdefault("limitations", [])
    item.setdefault("relationships", [])
    item["check_id"] = check_id
    item["check_index"] = index
    if category:
        item["category"] = category
    return item


async def _run_single_check(
    title: str,
    category: str | None,
    check: Awaitable[Any],
    query: str,
    check_id: str | None = None,
) -> list[dict]:
    check_id = check_id or str(uuid.uuid4())
    try:
        result = await check
        results = result if isinstance(result, list) else [result]
        if not results or not all(isinstance(item, dict) for item in results):
            raise TypeError(f"{title} returned an invalid result")
        return [
            _normalize_node(item, title, query, check_id, category, index)
            for index, item in enumerate(results)
        ]
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("OSINT check failed: %s", title)
        return [
            _normalize_node(
                {
                    "title": title,
                    "status": "error",
                    "fields": [{"label": "Ошибка", "value": "Проверка временно недоступна"}],
                },
                title,
                query,
                check_id,
                category,
                0,
            )
        ]


async def _collect_results(checks: list[tuple], query: str) -> list[dict]:
    outcome = await asyncio.gather(
        *(_run_single_check(check[0], _category_of(check), _coro_of(check), query) for check in checks),
        return_exceptions=True,
    )
    nodes: list[dict] = []
    for groups, outcome_item in zip(checks, outcome):
        if isinstance(outcome_item, asyncio.CancelledError):
            raise outcome_item
        if isinstance(outcome_item, Exception):
            logger.error("Check collection failed: %s: %s", groups[0], outcome_item)
            continue
        nodes.extend(outcome_item)
    return nodes


async def _gravatar_result(email: str) -> dict:
    email_hash = hashlib.md5(email.lower().encode(), usedforsecurity=False).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=False, trust_env=False) as client:
        try:
            response = await client.get(gravatar_url)
            if response.status_code == 200:
                return {
                    "title": "Gravatar",
                    "status": "completed",
                    "fields": [
                        {"label": "Статус", "value": "Найден"},
                        {"label": "Ссылка", "value": gravatar_url},
                    ],
                }
            return {
                "title": "Gravatar",
                "status": "no_results",
                "fields": [{"label": "Статус", "value": "Публичный аватар не найден"}],
            }
        except httpx.HTTPError:
            return {
                "title": "Gravatar",
                "status": "error",
                "fields": [{"label": "Ошибка", "value": "Сбой связи"}],
            }


async def _stream_checks(
    websocket: JSONSocket,
    checks: list[tuple],
    query: str = "",
) -> None:
    ready: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()

    async def run_check(title: str, category: str | None, check: Awaitable[Any]) -> None:
        check_id = str(uuid.uuid4())
        await ready.put(("loading", {"check_id": check_id, "title": title, "category": category}))
        results = await _run_single_check(title, category, check, query, check_id)
        await ready.put(("node", results))

    jobs = asyncio.gather(*(run_check(check[0], _category_of(check), _coro_of(check)) for check in checks))
    try:
        total = len(checks)
        completed_checks = 0
        result_count = 0
        loading_sent = 0
        completed_ids: set[str] = set()
        while loading_sent < total or completed_checks < total:
            kind, payload = await ready.get()
            if kind == "loading":
                loading_sent += 1
                await websocket.send_json({"type": "loading", "data": payload})
                continue
            for node in payload:
                await websocket.send_json({"type": "node", "data": node})
                result_count += 1
            check_id = payload[0].get("check_id") if payload else None
            if check_id and check_id not in completed_ids:
                completed_ids.add(check_id)
                completed_checks += 1
                await websocket.send_json({
                    "type": "progress",
                    "data": {
                        "completed": completed_checks,
                        "total": total,
                        "results": result_count,
                    },
                })
        await jobs
    finally:
        if not jobs.done():
            jobs.cancel()
            try:
                await jobs
            except asyncio.CancelledError:
                pass
def _classify_query(query: str, requested_type: Any) -> tuple[str | None, str | None]:
    allowed = {"email", "username", "domain", "ip", "url", "phone", "organization"}
    if requested_type is not None:
        if not isinstance(requested_type, str):
            return None, "Тип запроса должен быть строкой"
        if requested_type == "auto":
            requested_type = None
        else:
            if requested_type not in allowed:
                return None, "Неизвестный тип запроса"
            return requested_type, None
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", query):
        return "email", None
    if query.lower().startswith(("https://", "http://")):
        return "url", None
    try:
        ipaddress.ip_address(query)
        return "ip", None
    except ValueError:
        pass
    if re.fullmatch(r"\+?[0-9\s().-]+", query) and 10 <= len(re.sub(r"[^0-9]", "", query)) <= 15:
        return "phone", None
    try:
        normalize_public_hostname(query)
        return "domain", None
    except PublicHostError:
        return "username", None


def _validate_query(query: str, query_type: str) -> tuple[str, str | None]:
    if not query or len(query) > 255:
        return query, "Запрос должен содержать от 1 до 255 символов"
    if any(ord(character) < 32 for character in query):
        return query, "Запрос содержит недопустимые управляющие символы"
    if query_type == "email" and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", query):
        return query, "Укажите корректный email"
    if query_type == "domain":
        try:
            return normalize_public_hostname(query), None
        except PublicHostError as error:
            return query, str(error)
    if query_type == "ip":
        try:
            address = ipaddress.ip_address(query)
        except ValueError:
            return query, "Укажите корректный IP-адрес"
        if not address.is_global:
            return query, "Разрешены только публичные IP-адреса"
        return address.compressed, None
    if query_type == "url":
        try:
            parsed = urlsplit(query)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError:
            return query, "Некорректный URL"
        if (
            parsed.scheme not in {"http", "https"}
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
            or port not in {None, 80, 443}
        ):
            return query, "Допустим только HTTP(S) URL публичного hostname без авторизации и нестандартного порта"
        try:
            return normalize_public_hostname(hostname), None
        except PublicHostError as error:
            return query, str(error)
    if query_type == "phone":
        if not re.fullmatch(r"\+?[0-9\s().-]+", query) or not 10 <= len(re.sub(r"[^0-9]", "", query)) <= 15:
            return query, "Укажите телефон в международном формате"
    if query_type == "username" and (len(query) > 64 or any(character.isspace() for character in query)):
        return query, "Имя пользователя должно быть без пробелов и не длиннее 64 символов"
    if query_type == "organization" and not query.strip():
        return query, "Укажите название организации"
    return query, None


async def _compose_checks(query_type: str, query: str, depth: int) -> list[tuple]:
    """Единая композиция проверок для WebSocket-сканов и мониторинга."""
    if query_type == "email":
        _, domain = query.split("@", 1)
        checks = [
            ("SMTP & Домен", "mail", check_email_infrastructure(query)),
            ("Email в GitHub-коммитах", "profiles", check_github_commits(query)),
            ("Утечки (HIBP)", "leaks", check_hibp(query)),
            ("PGP Ключ", "profiles", check_pgp(query)),
            ("Gravatar", "profiles", _gravatar_result(query)),
        ]
        checks.extend(await get_domain_checks(domain, depth))
        return checks
    if query_type == "domain":
        return await get_domain_checks(query, depth)
    if query_type == "url":
        hostname = _validate_query(query, "url")[0]
        return await get_domain_checks(hostname, depth)
    if query_type == "ip":
        return [("RDAP / IP", "dns", get_ip_nodes(query))]
    if query_type == "phone":
        return [("Телефон", "phone", check_phone(query))]
    if query_type == "organization":
        return [
            ("Организации (Wikidata)", "org", check_wikidata_organization(query)),
            ("Организация GitHub", "org", check_github_organization(query)),
        ]
    return [
        ("GitHub profile", "profiles", check_username(query)),
        ("Email в GitHub-коммитах", "profiles", check_github_commits(query)),
        ("Профили (WhatsMyName)", "profiles", check_whatsmyname(query)),
    ]


@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    origin = websocket.headers.get("origin")
    if origin is not None and origin not in FRONTEND_ORIGINS:
        await websocket.close(code=1008, reason="Origin not allowed")
        return
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        raw_query = data.get("query") if isinstance(data, dict) else None
        query = raw_query.strip() if isinstance(raw_query, str) else ""
        query_type, type_error = _classify_query(
            query, data.get("query_type", data.get("input_type")) if isinstance(data, dict) else None
        )
        if type_error or query_type is None:
            await websocket.send_json({"error": type_error or "Неизвестный тип запроса"})
            return
        query, validation_error = _validate_query(query, query_type)
        if validation_error:
            await websocket.send_json({"error": validation_error})
            return
        depth = data.get("depth", 1)
        if isinstance(depth, bool) or not isinstance(depth, int) or depth not in (1, 2, 3):
            await websocket.send_json({"error": "Глубина поиска должна быть от 1 до 3"})
            return
        if depth > 1 and query_type not in {"email", "domain", "url"}:
            await websocket.send_json({"error": "Глубина поиска сейчас поддерживается только для email, домена и URL"})
            return
        checks = await _compose_checks(query_type, query, depth)
        retry_titles = data.get("retry_titles") if isinstance(data, dict) else None
        if retry_titles is not None:
            if (
                not isinstance(retry_titles, list)
                or not retry_titles
                or len(retry_titles) > 50
                or not all(isinstance(title, str) and 0 < len(title) <= 200 for title in retry_titles)
            ):
                await websocket.send_json({"error": "Список проверок для повтора некорректен"})
                return
            requested_titles = set(retry_titles)
            selected_checks = [check for check in checks if check[0] in requested_titles]
            for check in checks:
                if check[0] not in requested_titles:
                    close = getattr(_coro_of(check), "close", None)
                    if close:
                        close()
            checks = selected_checks
            if not checks:
                await websocket.send_json({"error": "Не найдено проверок для повтора"})
                return
        await websocket.send_json(
            {"type": "root", "data": {"query": query, "input_type": query_type, "depth": depth}}
        )
        await _stream_checks(websocket, checks, query)
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


DB_PATH = Path(__file__).resolve().parent / "monitoring.db"
MONITOR_TICK_SECONDS = 30.0
WATCH_INTERVAL_LIMITS = (5, 1440)  # минут


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS watches (
            id TEXT PRIMARY KEY,
            query TEXT NOT NULL,
            query_type TEXT NOT NULL,
            depth INTEGER NOT NULL,
            interval_minutes INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            next_run_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS watch_runs (
            watch_id TEXT NOT NULL,
            run_at TEXT NOT NULL,
            nodes_json TEXT NOT NULL,
            diff_json TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def _diff_nodes(previous: list[dict], current: list[dict]) -> dict:
    previous_by_title = {str(node.get("title") or ""): node for node in previous}
    current_by_title = {str(node.get("title") or ""): node for node in current}
    added = [title for title in current_by_title if title not in previous_by_title]
    removed = [title for title in previous_by_title if title not in current_by_title]
    changed = [
        {
            "title": title,
            "from": previous_by_title[title].get("state"),
            "to": current_by_title[title].get("state"),
        }
        for title in current_by_title
        if title in previous_by_title
        and previous_by_title[title].get("state") != current_by_title[title].get("state")
    ]
    return {"added": added[:20], "removed": removed[:20], "changed": changed[:20]}


async def _run_watch(watch: dict) -> None:
    watch_id = str(watch["id"])
    query_type = str(watch["query_type"])
    query = str(watch["query"])
    depth = int(watch["depth"])
    interval_minutes = int(watch["interval_minutes"])
    conn = _db()
    try:
        checks = await _compose_checks(query_type, query, depth)
        nodes = await _collect_results(checks, query)
        latest = conn.execute(
            "SELECT nodes_json FROM watch_runs WHERE watch_id = ? ORDER BY run_at DESC LIMIT 1",
            (watch_id,),
        ).fetchone()
        previous_nodes = json.loads(latest["nodes_json"]) if latest else []
        diff = _diff_nodes(previous_nodes, nodes)
        run_at = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO watch_runs (watch_id, run_at, nodes_json, diff_json) VALUES (?, ?, ?, ?)",
            (
                watch_id,
                run_at,
                json.dumps(nodes, ensure_ascii=False)[:2000000],
                json.dumps(diff, ensure_ascii=False),
            ),
        )
        conn.execute(
            "DELETE FROM watch_runs WHERE watch_id = ? AND run_at NOT IN (SELECT run_at FROM watch_runs WHERE watch_id = ? ORDER BY run_at DESC LIMIT 10)",
            (watch_id, watch_id),
        )
        conn.execute(
            "UPDATE watches SET next_run_at = ? WHERE id = ?",
            (time.time() + interval_minutes * 60.0, watch_id),
        )
        conn.commit()
        logger.info("Watch %s (%s) completed: %s nodes", watch_id, query, len(nodes))
    except Exception:
        logger.exception("Watch %s failed", watch_id)
        conn.execute(
            "UPDATE watches SET next_run_at = ? WHERE id = ?",
            (time.time() + max(interval_minutes, 5) * 60.0, watch_id),
        )
        conn.commit()
    finally:
        conn.close()


async def _monitor_loop() -> None:
    while True:
        try:
            conn = _db()
            try:
                due = conn.execute(
                    "SELECT * FROM watches WHERE next_run_at <= ?",
                    (time.time(),),
                ).fetchall()
            finally:
                conn.close()
            for row in due:
                asyncio.create_task(_run_watch(dict(row)))
        except Exception:
            logger.exception("Monitor loop iteration failed")
        await asyncio.sleep(MONITOR_TICK_SECONDS)


@app.get("/api/watch")
async def list_watches():
    conn = _db()
    try:
        rows = conn.execute("SELECT * FROM watches ORDER BY created_at DESC").fetchall()
        items = []
        for row in rows:
            latest = conn.execute(
                "SELECT run_at, diff_json, nodes_json FROM watch_runs WHERE watch_id = ? ORDER BY run_at DESC LIMIT 1",
                (row["id"],),
            ).fetchone()
            diff = json.loads(latest["diff_json"]) if latest else None
            nodes = json.loads(latest["nodes_json"]) if latest else []
            items.append({
                "id": row["id"],
                "query": row["query"],
                "query_type": row["query_type"],
                "depth": row["depth"],
                "interval_minutes": row["interval_minutes"],
                "created_at": row["created_at"],
                "next_run_in_minutes": max(0, round((row["next_run_at"] - time.time()) / 60.0, 1))
                if latest
                else None,
                "last_run_at": latest["run_at"] if latest else None,
                "results": len(nodes),
                "diff": diff,
            })
        return {"watches": items}
    finally:
        conn.close()


@app.post("/api/watch")
async def create_watch(payload: dict):
    query = str(payload.get("query") or "").strip()
    query_type = payload.get("query_type")
    depth = payload.get("depth", 1)
    interval_minutes = payload.get("interval_minutes", 60)
    if not query or len(query) > 255:
        return {"error": "Некорректный запрос"}
    if query_type not in {"email", "username", "domain", "ip", "url", "phone", "organization"}:
        return {"error": "Укажите явный тип запроса"}
    query, validation_error = _validate_query(query, query_type)
    if validation_error:
        return {"error": validation_error}
    if isinstance(depth, bool) or not isinstance(depth, int) or depth not in (1, 2, 3):
        return {"error": "Глубина должна быть 1–3"}
    if isinstance(interval_minutes, bool) or not isinstance(interval_minutes, int) or not (
        WATCH_INTERVAL_LIMITS[0] <= interval_minutes <= WATCH_INTERVAL_LIMITS[1]
    ):
        return {"error": f"Интервал — от {WATCH_INTERVAL_LIMITS[0]} до {WATCH_INTERVAL_LIMITS[1]} минут"}
    watch_id = str(uuid.uuid4())
    conn = _db()
    try:
        conn.execute(
            "INSERT INTO watches (id, query, query_type, depth, interval_minutes, created_at, next_run_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                watch_id,
                query,
                query_type,
                depth,
                interval_minutes,
                datetime.now(timezone.utc).isoformat(),
                time.time() + 5.0,  # первая перепроверка почти сразу
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return {"id": watch_id}


@app.delete("/api/watch/{watch_id}")
async def delete_watch(watch_id: str):
    conn = _db()
    try:
        cursor = conn.execute("DELETE FROM watches WHERE id = ?", (watch_id,))
        conn.execute("DELETE FROM watch_runs WHERE watch_id = ?", (watch_id,))
        conn.commit()
        return {"deleted": cursor.rowcount > 0}
    finally:
        conn.close()