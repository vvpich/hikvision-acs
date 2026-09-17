"""Интеграция Hikvision Access Control (события авторизации + фото)."""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant

from .alertstream import HikvisionAlertStreamClient, classify_event
from .const import CONF_VERIFY_SSL, DOMAIN, EVENT_BUS_EVENT

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
        # Фото всегда перезаписываем -- иначе к событию без фото прилипает
        # снимок предыдущего человека.
        data.last_photo = photo
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
