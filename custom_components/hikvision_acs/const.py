"""Константы интеграции Hikvision Access Control."""
from __future__ import annotations

DOMAIN = "hikvision_acs"

CONF_VERIFY_SSL = "verify_ssl"

DEFAULT_PORT = 443
DEFAULT_VERIFY_SSL = False
DEFAULT_NAME = "Hikvision Access Control"

ALERT_STREAM_PATH = "/ISAPI/Event/notification/alertStream?format=json"
DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo?format=json"

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
    (5, 75): "face_authenticated",
    (5, 76): "face_auth_failed",
    (5, 38): "card_authenticated",
    (5, 113): "fingerprint_authenticated",
    (5, 27): "exit_button_pressed",
}

# Какие события считаем "успешной авторизацией" для целей camera/last_user
SUCCESS_EVENT_TYPES = {
    "face_authenticated",
    "card_authenticated",
    "fingerprint_authenticated",
}

ALL_EVENT_TYPES = sorted(set(EVENT_LABELS.values()) | {"unknown_access_event"})

SIGNAL_NEW_EVENT = f"{DOMAIN}_new_event"
SIGNAL_CONNECTION_STATE = f"{DOMAIN}_connection_state"

# Событие на шине HA: hikvision_acs_event (для триггеров trigger: event)
EVENT_BUS_EVENT = f"{DOMAIN}_event"
