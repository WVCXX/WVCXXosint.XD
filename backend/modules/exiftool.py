import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
import uuid

logger = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
PROCESS_TIMEOUT = 20
INTERESTING_KEYS = (
    "Make",
    "Model",
    "Software",
    "Artist",
    "Author",
    "Copyright",
    "Creator",
    "DateTimeOriginal",
    "CreateDate",
    "ModifyDate",
    "ImageSize",
    "Megapixels",
    "GPSLatitude",
    "GPSLongitude",
    "Comment",
)
GROUP_PREFIXES = ("EXIF", "FILE", "GPS", "IPTC", "XMP", "MAKERNOTES")


def _safe_suffix(filename: str) -> str:
    suffix = os.path.splitext(os.path.basename(filename))[1][:12].lower()
    return suffix if suffix.replace(".", "").isalnum() else ".bin"


def _pick_fields(tags: dict) -> list[dict]:
    fields = []
    for key in INTERESTING_KEYS:
        value = tags.get(key)
        if value is None:
            for group in GROUP_PREFIXES:
                value = tags.get(f"{group}:{key}")
                if value is not None:
                    break
        if value is None:
            continue
        fields.append({"label": key, "value": str(value)[:200]})
    return fields


def _run_exiftool(binary: str, path: str) -> dict:
    process = subprocess.run(
        [binary, "-j", "-G", "-a", "--", path],
        capture_output=True,
        timeout=PROCESS_TIMEOUT,
    )
    if process.returncode != 0:
        stderr = process.stderr.decode("utf-8", errors="ignore")[:200]
        raise RuntimeError(stderr or "exiftool failed")
    payload = json.loads(process.stdout.decode("utf-8", errors="ignore") or "[]")
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
        raise ValueError("Unexpected exiftool output")
    return payload[0]


async def read_metadata(filename: str, content: bytes) -> dict:
    title = "ExifTool"
    source_url = "https://exiftool.org/"
    if not shutil.which("exiftool"):
        return {
            "title": title,
            "status": "not_configured",
            "source_url": source_url,
            "fields": [{"label": "Статус", "value": "exiftool не установлен на сервере; файл не был обработан"}],
        }
    if not content or len(content) > MAX_UPLOAD_BYTES:
        return {
            "title": title,
            "status": "error",
            "source_url": source_url,
            "fields": [{"label": "Ошибка", "value": "Файл отсутствует или превышает допустимый размер"}],
        }
    path = os.path.join(tempfile.gettempdir(), f"osint-exif-{uuid.uuid4().hex}{_safe_suffix(filename)}")
    try:
        def _write():
            with open(path, "wb") as handle:
                handle.write(content)

        await asyncio.to_thread(_write)
        tags = await asyncio.to_thread(_run_exiftool, shutil.which("exiftool"), path)
        fields = _pick_fields(tags)
        if not fields:
            return {
                "title": title,
                "status": "no_results",
                "source_url": source_url,
                "fields": [{"label": "Статус", "value": "Интересных метаданных не найдено"}],
            }
        return {"title": title, "status": "completed", "source_url": None, "fields": fields}
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        logger.warning("ExifTool failed for %s: %s", filename, error)
        return {
            "title": title,
            "status": "error",
            "source_url": source_url,
            "fields": [{"label": "Ошибка", "value": "Не удалось обработать файл метаданными ExifTool"}],
        }
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
