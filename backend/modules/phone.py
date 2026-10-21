import phonenumbers
from phonenumbers import geocoder, carrier
async def check_phone(phone: str):
    try:
        if not phone.startswith('+'):
            phone = '+' + phone
        parsed = phonenumbers.parse(phone, None)
        if not phonenumbers.is_valid_number(parsed):
            return {"title": "Телефон", "status": "error", "fields": [{"label": "Ошибка", "value": "Неверный формат"}]}
        region = geocoder.description_for_number(parsed, "ru")
        carrier_name = carrier.name_for_number(parsed, "ru")
        return {
            "title": "Информация о телефоне",
            "status": "ok",
            "fields": [
                {"label": "Регион", "value": region or "Неизвестно"},
                {"label": "Оператор", "value": carrier_name or "Неизвестно"}
            ]
        }
    except (phonenumbers.NumberParseException, ValueError):
        return {"title": "Телефон", "status": "error", "fields": [{"label": "Ошибка", "value": "Не удалось разобрать номер"}]}