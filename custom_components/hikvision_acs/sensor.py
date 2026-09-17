"""Вспомогательные сенсоры: последний пользователь/метод/статус."""
from __future__ import annotations

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_NAME, CONF_PORT
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, SUCCESS_EVENT_TYPES


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    stored = hass.data[DOMAIN][entry.entry_id]
    data = stored["data"]
    async_add_entities(
        [
            HikAcsLastUserSensor(entry, data),
            HikAcsLastMethodSensor(entry, data),
            HikAcsConnectionSensor(entry, data),
        ]
    )


class _BaseHikAcsSensor(SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, entry: ConfigEntry, data, key: str) -> None:
        self._data = data
        self._attr_unique_id = f"{entry.entry_id}_{key}"
        self.entity_description = SensorEntityDescription(key=key, translation_key=key)
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=entry.data.get(CONF_NAME) or entry.data[CONF_HOST],
            manufacturer="Hikvision",
            configuration_url=f"https://{entry.data[CONF_HOST]}:{entry.data[CONF_PORT]}",
        )
        self._remove_listener = None

    async def async_added_to_hass(self) -> None:
        self._remove_listener = self._data.add_listener(self._on_update)

    async def async_will_remove_from_hass(self) -> None:
        if self._remove_listener:
            self._remove_listener()

    def _on_update(self) -> None:
        self.async_write_ha_state()


class HikAcsLastUserSensor(_BaseHikAcsSensor):
    def __init__(self, entry: ConfigEntry, data) -> None:
        super().__init__(entry, data, "last_user")

    @property
    def native_value(self) -> str | None:
        if self._data.last_event_type in SUCCESS_EVENT_TYPES:
            return self._data.last_event_attrs.get("name")
        return None


class HikAcsLastMethodSensor(_BaseHikAcsSensor):
    def __init__(self, entry: ConfigEntry, data) -> None:
        super().__init__(entry, data, "last_method")

    @property
    def native_value(self) -> str | None:
        return self._data.last_event_type


class HikAcsConnectionSensor(_BaseHikAcsSensor):
    def __init__(self, entry: ConfigEntry, data) -> None:
        super().__init__(entry, data, "isapi_connection")

    @property
    def native_value(self) -> str:
        return "online" if self._data.connected else "offline"
