from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from collections.abc import Awaitable
from typing import Any, Protocol
from datetime import datetime, timezone
import ipaddress
import uuid
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
    from .modules.config import HIBP_API_KEY
    from .modules.email_infrastructure import check_email_infrastructure
    from .modules.github_commits import check_github_commits
    from .modules.harvester import run_theharvester
    from .modules.phone import check_phone
    from .modules.public_host import (
        PublicHostError,
        normalize_public_hostname,
        resolve_public_addresses,
    )
    from .modules.shodan import check_shodan
    from .modules.whois import check_whois
    from .modules.registry import get_tools
else:
    from modules.config import HIBP_API_KEY
    from modules.email_infrastructure import check_email_infrastructure
    from modules.github_commits import check_github_commits
    from modules.harvester import run_theharvester
    from modules.phone import check_phone
    from modules.public_host import (
        PublicHostError,
        normalize_public_hostname,
        resolve_public_addresses,
    )
    from modules.shodan import check_shodan
    from modules.whois import check_whois
    from modules.registry import get_tools

logger = logging.getLogger(__name__)


class JSONSocket(Protocol):
    async def send_json(self, data: Any) -> None: ...


app = FastAPI()
FRONTEND_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/tools")
async def tools_catalog():
    return {"tools": get_tools()}


async def check_hibp(email: str):
    if not HIBP_API_KEY:
        return {
            "title": "Утечки (HIBP)",
            "status": "not_configured",
            "fields": [{"label": "Статус", "value": "Добавьте HIBP_API_KEY в backend/.env"}],
        }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}?truncateResponse=false"
    headers = {"User-Agent": "OSINT-Spider-MVP"}
    headers["hibp-api-key"] = HIBP_API_KEY
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
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, trust_env=False) as client:
            response = await client.get(url, headers={"Accept": "application/vnd.github+json"})
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
                                extensions={"sni_hostname": hostname.encode("ascii")},
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
                        extensions={"sni_hostname": domain.encode("ascii")},
                    )
                    soup = BeautifulSoup(res.text, 'html.parser')
                    title = soup.title.string.strip() if soup.title else "Нет заголовка"
                    return {"title": "Веб-сайт", "status": "completed", "fields": [{"label": "HTTP", "value": str(res.status_code)}, {"label": "Title", "value": title}]}
                except httpx.HTTPError:
                    continue
        return {"title": "Веб-сайт", "status": "error", "fields": [{"label": "Ошибка", "value": "Сайт недоступен"}]}
    checks = [
        ("MX records", dns_mx()),
        ("IP addresses", dns_ip()),
        ("Shodan", shodan_lookup()),
        ("Website metadata", web_title()),
        ("TheHarvester", run_theharvester(domain)),
        ("WHOIS", check_whois(domain)),
    ]
    if depth > 1:
        checks.append(("Certificate Transparency", check_certificate_transparency(domain, depth - 1)))
    return checks


async def get_domain_nodes(domain: str, depth: int = 1) -> list[dict]:
    checks = await get_domain_checks(domain, depth)
    results = await asyncio.gather(*(check for _, check in checks), return_exceptions=True)
    nodes = []
    for (title, _), res in zip(checks, results):
        if isinstance(res, asyncio.CancelledError):
            raise res
        if isinstance(res, Exception):
            logger.error("Domain check failed: %s: %s", title, res)
            nodes.append({
                "title": title,
                "status": "error",
                "fields": [{"label": "Ошибка", "value": "Проверка временно недоступна"}],
            })
            continue
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
    checks: list[tuple[str, Awaitable[Any]]],
    query: str = "",
) -> None:
    ready: asyncio.Queue[Any] = asyncio.Queue()
    source_urls = {
        "SMTP & Домен": "https://www.rfc-editor.org/rfc/rfc1035",
        "MX Записи": "https://www.rfc-editor.org/rfc/rfc1035",
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
        "Shodan (Порты)": "https://developer.shodan.io/api",
    }
    execution_states = {
        "ok": "completed",
        "completed": "completed",
        "error": "failed",
        "no_results": "no_results",
        "partial": "partial",
        "info": "partial",
        "not_configured": "not_configured",
        "rate_limited": "rate_limited",
    }

    async def run_check(title: str, check: Awaitable[Any]) -> None:
        try:
            result = await check
            results = result if isinstance(result, list) else [result]
            if not all(isinstance(item, dict) for item in results):
                raise TypeError(f"{title} returned an invalid result")
            for item in results:
                if not isinstance(item.get("fields"), list):
                    item["fields"] = []
                status = item.get("status", "info")
                item.setdefault("id", str(uuid.uuid4()))
                item.setdefault("query", query)
                item.setdefault("tool", item.get("title", title))
                item.setdefault("received_at", datetime.now(timezone.utc).isoformat())
                item.setdefault("entity_type", "OSINT Module")
                item.setdefault("state", execution_states.get(status, "partial"))
                item.setdefault("source_url", source_urls.get(item.get("title", title)))
                item.setdefault("confidence", None)
                item.setdefault("evidence_type", "source_response")
                item.setdefault("errors", [
                    str(field.get("value", ""))
                    for field in item["fields"]
                    if isinstance(field, dict) and field.get("label") == "Ошибка"
                ])
                item.setdefault("limitations", [])
                item.setdefault("relationships", [])
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
        completed_checks = 0
        result_count = 0
        for _ in checks:
            result = await ready.get()
            results = result if isinstance(result, list) else [result]
            for node in results:
                if isinstance(node, dict):
                    await websocket.send_json({"type": "node", "data": node})
                    result_count += 1
            completed_checks += 1
            await websocket.send_json({
                "type": "progress",
                "data": {
                    "completed": completed_checks,
                    "total": len(checks),
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
        await websocket.send_json(
            {"type": "root", "data": {"query": query, "input_type": query_type, "depth": depth}}
        )
        if query_type == "email":
            _, domain = query.split("@", 1)
            checks = [
                ("SMTP & Домен", check_email_infrastructure(query)),
                ("Email в GitHub-коммитах", check_github_commits(query)),
                ("Утечки (HIBP)", check_hibp(query)),
                ("PGP Ключ", check_pgp(query)),
                ("Gravatar", _gravatar_result(query)),
            ]
            checks.extend(await get_domain_checks(domain, depth))
            await _stream_checks(websocket, checks, query)
        elif query_type == "domain":
            await _stream_checks(websocket, await get_domain_checks(query, depth), query)
        elif query_type == "url":
            hostname = _validate_query(query, "url")[0]
            await _stream_checks(websocket, await get_domain_checks(hostname, depth), query)
        elif query_type == "ip":
            await _stream_checks(websocket, [("IP Intelligence", get_ip_nodes(query))], query)
        elif query_type == "phone":
            await _stream_checks(websocket, [("Телефон", check_phone(query))], query)
        elif query_type == "organization":
            await _stream_checks(websocket, [("Организация", asyncio.sleep(0, result={
                "title": "Реестры организаций",
                "status": "not_configured",
                "fields": [{"label": "Статус", "value": "Адаптер публичного реестра не подключён"}],
            }))], query)
        else:
            await _stream_checks(
                websocket,
                [
                    ("GitHub profile", check_username(query)),
                    ("Email в GitHub-коммитах", check_github_commits(query)),
                ],
                query,
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