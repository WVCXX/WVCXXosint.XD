import asyncio
import re
import dns.asyncresolver
import dns.exception
import dns.resolver
def _normalize_domain(email: str) -> str | None:
    if email.count("@") != 1:
        return None
    local_part, domain = email.split("@", 1)
    if not local_part or any(character.isspace() for character in local_part):
        return None
    domain = domain.rstrip(".")
    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(domain) > 253 or not re.fullmatch(
        r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*",
        domain,
    ):
        return None
    return domain
async def _resolve(record_name: str, record_type: str):
    try:
        return await dns.asyncresolver.resolve(record_name, record_type)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.DNSException as error:
        return error
def _txt_value(record) -> str:
    strings = getattr(record, "strings", None)
    if strings:
        return b"".join(strings).decode("utf-8", errors="replace")
    return str(record).strip('"')
def _provider(mx_server: str) -> str:
    mx = mx_server.lower()
    providers = {
        "Google": ("google.com", "googlemail.com"),
        "Microsoft 365": ("outlook.com", "protection.outlook.com"),
        "Proton Mail": ("protonmail.ch", "protonmail.net"),
        "Zoho": ("zoho.com", "zohomail.com"),
    }
    for provider, markers in providers.items():
        if any(mx == marker or mx.endswith(f".{marker}") for marker in markers):
            return provider
    return "Собственный/неизвестный"
async def check_email_infrastructure(email: str) -> dict:
    domain = _normalize_domain(email.strip())
    if domain is None:
        return {
            "title": "SMTP & Домен",
            "status": "error",
            "fields": [{"label": "Ошибка", "value": "Некорректный email или домен"}],
        }
    mx_records, root_txt, dmarc_txt = await asyncio.gather(
        _resolve(domain, "MX"),
        _resolve(domain, "TXT"),
        _resolve(f"_dmarc.{domain}", "TXT"),
    )
    errors = [
        result
        for result in (mx_records, root_txt, dmarc_txt)
        if isinstance(result, dns.exception.DNSException)
    ]
    mx_servers = (
        sorted(str(record.exchange).rstrip(".") for record in mx_records)
        if not isinstance(mx_records, Exception)
        else []
    )
    txt_values = (
        [_txt_value(record) for record in root_txt]
        if not isinstance(root_txt, Exception)
        else []
    )
    dmarc_values = (
        [_txt_value(record) for record in dmarc_txt]
        if not isinstance(dmarc_txt, Exception)
        else []
    )
    mx_server = ", ".join(mx_servers) if mx_servers else (
        "Не удалось проверить" if isinstance(mx_records, Exception) else "Не найден"
    )
    mx_status = (
        "Не удалось проверить"
        if isinstance(mx_records, Exception)
        else ("MX-записи найдены" if mx_servers else "MX-записи не найдены")
    )
    spf_configured = any(value.lower().startswith("v=spf1") for value in txt_values)
    dmarc_configured = any(value.lower().startswith("v=dmarc1") for value in dmarc_values)
    spf_status = (
        "не удалось проверить"
        if isinstance(root_txt, Exception)
        else ("настроен" if spf_configured else "не найден")
    )
    dmarc_status = (
        "не удалось проверить"
        if isinstance(dmarc_txt, Exception)
        else ("настроен" if dmarc_configured else "не найден")
    )
    security = (
        f"SPF: {spf_status}; DMARC: {dmarc_status}"
    )
    status = "error" if errors else ("ok" if mx_servers else "info")
    if errors and mx_servers:
        status = "info"
    return {
        "title": "SMTP & Домен",
        "status": status,
        "fields": [
            {"label": "Провайдер", "value": _provider(mx_servers[0]) if mx_servers else "Не определён"},
            {"label": "MX Сервер", "value": mx_server},
            {"label": "MX-записи", "value": mx_status},
            {"label": "Безопасность", "value": security},
        ],
    }
