"""Event-сущность: одно событие на каждую авторизацию/алярм."""
from __future__ import annotations

from homeassistant.components.event import EventEntity, EventEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_NAME, CONF_PORT
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import ALL_EVENT_TYPES, DOMAIN


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    stored = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([HikAcsEventEntity(entry, stored["data"])])


class HikAcsEventEntity(EventEntity):
    """Фиксирует каждое событие авторизации как HA event."""

    _attr_has_entity_name = True
    _attr_translation_key = "access_event"
    entity_description = EventEntityDescription(
        key="access_event",
        translation_key="access_event",
    )

    def __init__(self, entry: ConfigEntry, data) -> None:
        self._entry = entry
        self._data = data
        self._attr_unique_id = f"{entry.entry_id}_access_event"
        self._attr_event_types = ALL_EVENT_TYPES
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=entry.data.get(CONF_NAME) or entry.data[CONF_HOST],
            manufacturer="Hikvision",
            configuration_url=f"https://{entry.data[CONF_HOST]}:{entry.data[CONF_PORT]}",
        )
        self._remove_listener = None
        self._last_seen_seq = 0

    async def async_added_to_hass(self) -> None:
        self._remove_listener = self._data.add_listener(self._handle_update)

    async def async_will_remove_from_hass(self) -> None:
        if self._remove_listener:
            self._remove_listener()

    def _handle_update(self) -> None:
        event_type = self._data.last_event_type
        seq = self._data.event_seq
        if event_type is None or seq == self._last_seen_seq:
            return  # нотификация не про новое событие (например, смена статуса связи)
        self._last_seen_seq = seq
        self._trigger_event(event_type, dict(self._data.last_event_attrs))
        self.async_write_ha_state()
