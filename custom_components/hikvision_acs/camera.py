"""Camera-сущность: последнее фото авторизации."""
from __future__ import annotations

from homeassistant.components.camera import Camera
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_NAME, CONF_PORT
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    stored = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([HikAcsLastPhotoCamera(entry, stored["data"])])


class HikAcsLastPhotoCamera(Camera):
    """Отдаёт JPEG последнего события с фото (если оно было в payload)."""

    _attr_has_entity_name = True
    _attr_translation_key = "last_access_photo"

    def __init__(self, entry: ConfigEntry, data) -> None:
        super().__init__()
        self._data = data
        self._attr_unique_id = f"{entry.entry_id}_last_access_photo"
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
        # Реагируем только на авторизации: door_opened приходит следом за
        # проходом и сбросил бы только что полученный снимок. Состояние
        # пишем и когда фото пропало, чтобы не отдавать кадр от предыдущего
        # человека.
        if self._data.auth_seq != self._last_seen_seq:
            self._last_seen_seq = self._data.auth_seq
            self.async_write_ha_state()

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        return self._data.last_photo
