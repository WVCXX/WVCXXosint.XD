import asyncio
import ipaddress
import re

import dns.asyncresolver
import dns.exception
import dns.resolver


class PublicHostError(ValueError):
    pass


def normalize_public_hostname(value: str) -> str:
    candidate = value.strip().rstrip(".")
    if not candidate or any(character in candidate for character in "/\\@:#?%"):
        raise PublicHostError("Укажите только hostname без URL, порта или пути")

    try:
        hostname = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise PublicHostError("Некорректное имя хоста") from error

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise PublicHostError("IP-адреса для проверки не принимаются")

    labels = hostname.split(".")
    if (
        len(hostname) > 253
        or len(labels) < 2
        or any(
            len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        )
    ):
        raise PublicHostError("Некорректное имя хоста")

    return hostname


async def resolve_public_addresses(hostname: str) -> list[str]:
    answers = await asyncio.gather(
        dns.asyncresolver.resolve(hostname, "A"),
        dns.asyncresolver.resolve(hostname, "AAAA"),
        return_exceptions=True,
    )
    addresses = set()
    for answer in answers:
        if isinstance(answer, Exception):
            if isinstance(answer, (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN)):
                continue
            if isinstance(answer, dns.exception.DNSException):
                raise PublicHostError("Не удалось безопасно проверить DNS-ответ") from answer
            raise PublicHostError("Не удалось безопасно проверить DNS-ответ") from answer

        for record in answer:
            try:
                address = ipaddress.ip_address(record.address)
            except (AttributeError, ValueError) as error:
                raise PublicHostError("DNS вернул некорректный IP-адрес") from error
            if not address.is_global:
                raise PublicHostError("Hostname разрешается в непубличный IP-адрес")
            addresses.add(address.compressed)

    if not addresses:
        raise PublicHostError("Для hostname не найдены публичные A/AAAA записи")

    return sorted(addresses, key=lambda address: (":" in address, address))
