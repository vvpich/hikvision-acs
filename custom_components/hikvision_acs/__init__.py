"""Интеграция Hikvision Access Control (события авторизации + фото)."""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .alertstream import HikvisionAlertStreamClient, async_fetch_json, classify_event
from .const import (
    ACS_CFG_PATH,
    AUTH_EVENT_TYPES,
    CONF_VERIFY_SSL,
    DOMAIN,
    EVENT_BUS_EVENT,
    PICTURE_UPLOAD_FLAGS,
    SUCCESS_EVENT_TYPES,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.EVENT, Platform.CAMERA, Platform.SENSOR]


@dataclass
class HikAcsRuntimeData:
    """Общее push-состояние, на которое подписываются сущности."""

    connected: bool = False
    last_error: str | None = None
    # Монотонный счётчик: сущности сравнивают его, чтобы отличить новое
    # событие от повторной нотификации (два одинаковых прохода подряд
    # дают одинаковые атрибуты, но разный seq).
    event_seq: int = 0
    last_event_type: str | None = None
    last_event_attrs: dict = field(default_factory=dict)
    # Отдельное состояние авторизаций: служебные события вроде door_opened
    # приходят следом за проходом и не должны затирать фото и имя.
    auth_seq: int = 0
    last_auth_type: str | None = None
    last_auth_attrs: dict = field(default_factory=dict)
    last_user: str | None = None
    last_photo: bytes | None = None
    _listeners: list[Callable[[], None]] = field(default_factory=list)

    def add_listener(self, callback: Callable[[], None]) -> Callable[[], None]:
        self._listeners.append(callback)

        def _remove() -> None:
            if callback in self._listeners:
                self._listeners.remove(callback)

        return _remove

    def notify(self) -> None:
        for cb in list(self._listeners):
            cb()


async def _async_warn_if_pictures_disabled(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Без uploadCapPic/uploadVerificationPic терминал не вкладывает JPEG.

    Диагностика: иначе пустая camera.* выглядит как баг интеграции, хотя
    дело в настройках устройства.
    """
    base_url = f"https://{entry.data[CONF_HOST]}:{entry.data[CONF_PORT]}"
    session = async_get_clientsession(hass, verify_ssl=entry.data[CONF_VERIFY_SSL])
    try:
        payload = await async_fetch_json(
            session,
            base_url,
            ACS_CFG_PATH,
            entry.data[CONF_USERNAME],
            entry.data[CONF_PASSWORD],
            entry.data[CONF_VERIFY_SSL],
        )
    except Exception as exc:  # noqa: BLE001 -- диагностика не должна ломать запуск
        _LOGGER.debug("Не удалось прочитать %s: %s", ACS_CFG_PATH, exc)
        return

    cfg = payload.get("AcsCfg", {})
    disabled = [flag for flag in PICTURE_UPLOAD_FLAGS if cfg.get(flag) is False]
    if disabled:
        _LOGGER.warning(
            "Терминал не будет присылать фото: в /ISAPI/AccessControl/AcsCfg "
            "выключено %s. Пока это так, camera.* останется пустой -- "
            "включается в настройках устройства, см. README.",
            ", ".join(disabled),
        )
    else:
        _LOGGER.debug("Загрузка снимков на терминале включена: %s", cfg)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = HikAcsRuntimeData()

    async def _on_event(event_json: dict, photo: bytes | None) -> None:
        classified = classify_event(event_json)
        if classified is None:
            return
        event_type, attrs = classified
        data.event_seq += 1
        data.last_event_type = event_type
        data.last_event_attrs = attrs
        if event_type in AUTH_EVENT_TYPES:
            data.auth_seq += 1
            data.last_auth_type = event_type
            data.last_auth_attrs = attrs
            # Фото перезаписываем всегда, в том числе в None -- иначе к
            # авторизации без снимка прилипает лицо предыдущего человека.
            data.last_photo = photo
            if event_type in SUCCESS_EVENT_TYPES:
                data.last_user = attrs.get("name")
        hass.bus.async_fire(
            EVENT_BUS_EVENT,
            {"entry_id": entry.entry_id, "event_type": event_type, "has_photo": photo is not None, **attrs},
        )
        data.notify()

    async def _on_connection_change(connected: bool, error: str | None) -> None:
        data.connected = connected
        data.last_error = error
        data.notify()

    client = HikvisionAlertStreamClient(
        host=entry.data[CONF_HOST],
        port=entry.data[CONF_PORT],
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        verify_ssl=entry.data[CONF_VERIFY_SSL],
        on_event=_on_event,
        on_connection_change=_on_connection_change,
    )

    entry.runtime_data = data
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {"client": client, "data": data}

    entry.async_create_background_task(
        hass, _async_warn_if_pictures_disabled(hass, entry), "hikvision_acs_acscfg"
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    # Запускаем поток только после того, как сущности созданы, иначе первые
    # события уйдут в пустоту.
    client.start()
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        stored = hass.data[DOMAIN].pop(entry.entry_id)
        await stored["client"].stop()
    return unload_ok
