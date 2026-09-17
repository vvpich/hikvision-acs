"""Config flow для Hikvision Access Control."""
from __future__ import annotations

import logging
from typing import Any

import aiohttp
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_NAME, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from .alertstream import async_build_auth_header
from .const import CONF_VERIFY_SSL, DEFAULT_NAME, DEFAULT_PORT, DEFAULT_VERIFY_SSL, DEVICE_INFO_PATH, DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_NAME, default=DEFAULT_NAME): str,
        vol.Optional(CONF_VERIFY_SSL, default=DEFAULT_VERIFY_SSL): bool,
    }
)


class CannotConnect(HomeAssistantError):
    """Не удалось подключиться к терминалу."""


class InvalidAuth(HomeAssistantError):
    """Неверный логин/пароль."""


async def _validate_connection(hass: HomeAssistant, data: dict[str, Any]) -> None:
    """Быстрая проверка: пробуем авторизацию (Digest/Basic) на /System/deviceInfo."""
    url = f"https://{data[CONF_HOST]}:{data[CONF_PORT]}{DEVICE_INFO_PATH}"
    timeout = aiohttp.ClientTimeout(total=10)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            auth_header = await async_build_auth_header(
                session,
                url,
                DEVICE_INFO_PATH,
                data[CONF_USERNAME],
                data[CONF_PASSWORD],
                data[CONF_VERIFY_SSL],
            )
        except aiohttp.ClientError as exc:
            raise CannotConnect(str(exc)) from exc
        except RuntimeError as exc:
            raise CannotConnect(str(exc)) from exc

        if auth_header is None:
            return  # устройство отдало 200 без аутентификации

        try:
            async with session.get(
                url, ssl=data[CONF_VERIFY_SSL], headers={"Authorization": auth_header}
            ) as resp:
                if resp.status == 401:
                    raise InvalidAuth("Неверный логин или пароль")
                if resp.status != 200:
                    raise CannotConnect(f"Неожиданный статус {resp.status}")
        except aiohttp.ClientError as exc:
            raise CannotConnect(str(exc)) from exc


class HikvisionAcsConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow для Hikvision Access Control."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            await self.async_set_unique_id(f"{user_input[CONF_HOST]}:{user_input[CONF_PORT]}")
            self._abort_if_unique_id_configured()

            try:
                await _validate_connection(self.hass, user_input)
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Неожиданная ошибка при проверке подключения")
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(
                    title=user_input.get(CONF_NAME, DEFAULT_NAME), data=user_input
                )

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_SCHEMA, errors=errors
        )
