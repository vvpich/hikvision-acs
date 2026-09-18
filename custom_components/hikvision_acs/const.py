"""Константы интеграции Hikvision Access Control."""
from __future__ import annotations

DOMAIN = "hikvision_acs"

CONF_VERIFY_SSL = "verify_ssl"
# Экспериментально: подписка с pictureURLType=binary ради фото в потоке.
# По умолчанию выключено -- см. комментарий у SUBSCRIBE_EVENT_CANDIDATES.
CONF_SUBSCRIBE_PICTURES = "subscribe_pictures"

DEFAULT_PORT = 443
DEFAULT_VERIFY_SSL = False
DEFAULT_NAME = "Hikvision Access Control"

ALERT_STREAM_PATH = "/ISAPI/Event/notification/alertStream?format=json"
DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo?format=json"
ACS_CFG_PATH = "/ISAPI/AccessControl/AcsCfg?format=json"
SUBSCRIBE_EVENT_PATH = "/ISAPI/Event/notification/subscribeEvent"
SUBSCRIBE_TIMEOUT = 10

# Снимки попадают в поток только если подписка запрошена с
# pictureURLType=binary (/ISAPI/Event/notification/subscribeEventCap
# подтверждает поддержку: pictureURLType=binary,
# isSupportModifySubscribeEvent=true). minorEvent не перечисляем -- нужны
# все подтипы AccessControllerEvent, фильтруем уже у себя.
# Минорные коды AccessControllerEvent, которые устройство перечисляет в
# subscribeEventCap как доступные для подписки.
_MINOR_EVENT_CODES = (
    "0x1,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf,0x10,0x11,0x12,0x13,0x14,"
    "0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1f,0x20,0x21,0x22,0x23,0x24,"
    "0x26,0x27,0x31,0x33,0x4b,0x4c,0x50,0x5e,0x68,0x75,0x82,0x84,0x8e,0x97,"
    "0x98,0x9b,0xa4,0xa8,0xb5,0xc1,0x9f,0xa0"
)


def _subscribe_xml(event_mode: str, minor_event: str | None) -> str:
    minor = f"<minorEvent>{minor_event}</minorEvent>" if minor_event else ""
    return (
        '<SubscribeEvent version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema">'
        "<heartbeat>30</heartbeat>"
        "<channelMode>all</channelMode>"
        f"<eventMode>{event_mode}</eventMode>"
        "<EventList><Event>"
        "<type>AccessControllerEvent</type>"
        f"{minor}"
        "<pictureURLType>binary</pictureURLType>"
        "</Event></EventList>"
        "</SubscribeEvent>"
    )


# Прошивки расходятся в том, какие поля считают обязательными, а ошибка
# приходит одна и та же (MessageParametersLack), без указания поля. Поэтому
# пробуем варианты по порядку и запоминаем сработавший.
SUBSCRIBE_EVENT_CANDIDATES = (
    ("list+minor", _subscribe_xml("list", _MINOR_EVENT_CODES)),
    ("list", _subscribe_xml("list", None)),
    ("all", _subscribe_xml("all", None)),
)

# Флаги AcsCfg, без которых терминал не вкладывает JPEG в событие.
# На заводских настройках DS-K1T342MFWX оба false.
PICTURE_UPLOAD_FLAGS = ("uploadCapPic", "uploadVerificationPic")

# Предохранитель: если boundary не находится, а буфер пухнет -- значит поток
# рассинхронизирован, лучше переподключиться, чем съесть всю память.
MAX_BUFFER_BYTES = 8 * 1024 * 1024

# Категории majorEventType в AccessControllerEvent:
#   1 MAJOR_ALARM     -- тревоги (взлом, тампер)
#   2 MAJOR_EXCEPTION -- неисправности
#   3 MAJOR_OPERATION -- операции с устройством (в т.ч. подключение ISAPI-
#                        клиента: 3/121 и 3/122 прилетают на каждый коннект
#                        самого Home Assistant)
#   5 MAJOR_EVENT     -- события доступа, то есть авторизации
# Интеграция публикует только MAJOR_EVENT: остальное шумит и к проходам
# людей отношения не имеет.
MAJOR_EVENT = 5

# Сколько serialNo помнить, чтобы не публиковать повторы: терминал при
# переподключении заново отдаёт последние записи журнала (currentEvent=false).
SEEN_SERIALS_MEMORY = 64

# Коды majorEventType/subEventType для AccessControllerEvent.
# Подтверждены официальным Hikvision ISAPI Developer Guide for Face
# Recognition Terminals (DS-K1T342MFWX явно в списке поддерживаемых
# моделей). Разные прошивки могут добавлять свои коды -- неизвестные
# пары публикуются как "unknown_<major>_<minor>", ничего не теряется.
EVENT_LABELS: dict[tuple[int, int], str] = {
    # Подтверждено на DS-K1T342MFWX (прошивка шлёт именно эти коды):
    (5, 1): "card_authenticated",
    (5, 21): "door_opened",
    (5, 22): "door_closed",
    # Из документации, на DS-K1T342MFWX не наблюдались -- другие прошивки
    # и другие способы верификации:
    (5, 27): "exit_button_pressed",
    (5, 38): "card_authenticated",
    (5, 75): "face_authenticated",
    (5, 76): "face_auth_failed",
    (5, 113): "fingerprint_authenticated",
}

# События, означающие попытку авторизации человека. Только они обновляют
# фото и сенсоры "последний пользователь/метод": door_opened приходит через
# доли секунды после прохода и иначе затирал бы и имя, и снимок.
AUTH_EVENT_TYPES = {
    "card_authenticated",
    "face_authenticated",
    "fingerprint_authenticated",
    "face_auth_failed",
}

# Какие из них считаем успешной авторизацией (для sensor.last_user)
SUCCESS_EVENT_TYPES = {
    "card_authenticated",
    "face_authenticated",
    "fingerprint_authenticated",
}

ALL_EVENT_TYPES = sorted(set(EVENT_LABELS.values()) | {"unknown_access_event"})

SIGNAL_NEW_EVENT = f"{DOMAIN}_new_event"
SIGNAL_CONNECTION_STATE = f"{DOMAIN}_connection_state"

# Событие на шине HA: hikvision_acs_event (для триггеров trigger: event)
EVENT_BUS_EVENT = f"{DOMAIN}_event"
