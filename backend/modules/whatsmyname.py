import asyncio
import logging
import time
from urllib.parse import quote, urljoin
import httpx
logger = logging.getLogger(__name__)
DATASET_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
DATASET_TTL_SECONDS = 3600
MAX_SITES = 40
MAX_CONCURRENCY = 8
REQUEST_TIMEOUT = 6.0
MAX_REDIRECT_HOPS = 3
_cache: dict[str, object] = {"loaded_at": 0.0, "dataset": []}
def classify_site_response(site: dict, status_code: int, body_text: str) -> str:
    expected_code = site.get("e_code")
    e_string = str(site.get("e_string") or "").lower()
    if status_code == expected_code and e_string and e_string in body_text.lower():
        return "confirmed"
    if status_code == expected_code:
        return "possible"
    if status_code in (404, 410):
        return "absent"
    return "inconclusive"
def _sites_from_dataset(payload: object) -> list[dict]:
    dataset = payload.get("sites") if isinstance(payload, dict) else payload
    if not isinstance(dataset, list):
        return []
    with_markers = []
    without = []
    for site in dataset:
        if not isinstance(site, dict):
            continue
        uri = str(site.get("uri_check") or "")
        if "{account}" not in uri or not uri.startswith("https://"):
            continue
        if str(site.get("method") or "GET").upper() not in ("", "GET"):
            continue
        if not isinstance(site.get("e_code"), int):
            continue
        if str(site.get("e_string") or "").strip():
            with_markers.append(site)
        else:
            without.append(site)
    return (with_markers + without)[:MAX_SITES]
async def _load_dataset() -> list:
    if _cache["dataset"] and time.time() - _cache["loaded_at"] < DATASET_TTL_SECONDS:
        return _cache["dataset"]
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, trust_env=False) as client:
        response = await client.get(DATASET_URL)
    if response.status_code != 200:
        raise httpx.HTTPStatusError(
            f"dataset HTTP {response.status_code}", request=response.request, response=response
        )
    payload = response.json()
    dataset = _sites_from_dataset(payload)
    if not dataset:
        raise ValueError("WhatsMyName dataset contains no usable GET sites")
    _cache["dataset"] = dataset
    _cache["loaded_at"] = time.time()
    return _cache["dataset"]
async def _probe_get(client: httpx.AsyncClient, url: str, headers: dict) -> httpx.Response:
    current = url
    for _ in range(MAX_REDIRECT_HOPS + 1):
        response = await client.get(current, headers=headers)
        if response.status_code not in (301, 302, 303, 307, 308):
            return response
        location = response.headers.get("location")
        if not location:
            return response
        next_url = urljoin(current, location)
        if not next_url.startswith("https://"):
            return response  # redirect на http — остаёмся с незавершённым ответом
        current = next_url
    return response
async def check_whatsmyname(username: str) -> dict:
    title = "Профили (WhatsMyName)"
    try:
        dataset = await _load_dataset()
    except Exception as error:
        logger.warning("WhatsMyName dataset unavailable: %s", error)
        return {
            "title": title,
            "status": "error",
            "source_url": "https://github.com/WebBreacher/WhatsMyName",
            "fields": [{"label": "Ошибка", "value": "Датасет WhatsMyName недоступен"}],
        }
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    counts = {"confirmed": [], "possible": [], "absent": 0, "inconclusive": 0, "error": 0}

    async def probe(site: dict) -> None:
        url = str(site["uri_check"]).format(account=quote(username, safe=""))
        async with semaphore:
            try:
                async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=False, trust_env=False) as client:
                    response = await _probe_get(client, url, {"User-Agent": "OSINT-Spider-MVP"})
                verdict = classify_site_response(site, response.status_code, response.text[:20000])
            except (httpx.HTTPError, ValueError):
                verdict = "error"
        if verdict in ("confirmed", "possible"):
            counts[verdict].append((str(site.get("name") or url), url))
        elif verdict in counts and isinstance(counts[verdict], int):
            counts[verdict] += 1
    await asyncio.gather(*(probe(site) for site in dataset))
    checked = len(dataset)
    confirmed_links = [url for _, url in counts["confirmed"]]
    possible_links = [url for _, url in counts["possible"]]
    failed_total = counts["error"] + counts["inconclusive"]
    if failed_total == checked:
        status = "error"
    elif confirmed_links:
        status = "completed"
    elif possible_links or counts["absent"] < checked:
        status = "partial"
    else:
        status = "no_results"
    fields = [
        {"label": "Проверено сайтов", "value": str(checked)},
        {"label": "Подтверждено", "value": ", ".join(name for name, _ in counts["confirmed"][:8]) if counts["confirmed"] else "Нет"},
        {"label": "Возможно (без точного совпадения)", "value": ", ".join(name for name, _ in counts["possible"][:8]) if counts["possible"] else "Нет"},
        {"label": "Не найдено", "value": str(counts["absent"])},
        {"label": "Неопределённых ответов", "value": str(counts["inconclusive"] + counts["error"])},
    ]
    if confirmed_links:
        fields.append({"label": "Ссылки", "value": ", ".join(confirmed_links[:5])})
    return {
        "title": title,
        "status": status,
        "source_url": "https://webbreacher.github.io/WhatsMyNameApp/",
        "fields": fields,
        "links": confirmed_links + possible_links,
    }
