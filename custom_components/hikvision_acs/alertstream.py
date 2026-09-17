"""Асинхронный клиент для /ISAPI/Event/notification/alertStream.

Реализует HTTP Digest и Basic вручную (aiohttp не имеет встроенной
поддержки Digest auth), держит постоянное соединение, разбирает
multipart/mixed поток на JSON-события (AccessControllerEvent) и
прикреплённые JPEG, с автоматическим реконнектом.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import aiohttp

from .const import ALERT_STREAM_PATH, EVENT_LABELS, MAX_BUFFER_BYTES

_LOGGER = logging.getLogger(__name__)

EventCallback = Callable[[dict, bytes | None], Awaitable[None]]
ConnectionCallback = Callable[[bool, str | None], Awaitable[None]]

_AUTH_PARAM_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s,]+))')


class AuthFailed(Exception):
    """Терминал отверг логин/пароль (401 после отправки credentials)."""


@dataclass
class _DigestChallenge:
    realm: str
    nonce: str
    qop: str | None
    opaque: str | None
    algorithm: str | None = None


def _parse_digest_challenge(header: str) -> _DigestChallenge:
    values: dict[str, str] = {}
    for m in _AUTH_PARAM_RE.finditer(header):
        key = m.group(1)
        values[key] = m.group(2) if m.group(2) is not None else m.group(3)

    qop = values.get("qop")
    if qop:
        # qop может быть списком ("auth,auth-int") -- поддерживаем только auth
        options = [opt.strip() for opt in qop.split(",")]
        qop = "auth" if "auth" in options else options[0]

    return _DigestChallenge(
        realm=values.get("realm", ""),
        nonce=values.get("nonce", ""),
        qop=qop,
        opaque=values.get("opaque"),
        algorithm=values.get("algorithm"),
    )


def _build_digest_header(
    username: str,
    password: str,
    method: str,
    uri: str,
    challenge: _DigestChallenge,
    nc: int,
) -> str:
    def md5(data: str) -> str:
        return hashlib.md5(data.encode()).hexdigest()  # noqa: S324 -- требование протокола Digest

    nc_str = f"{nc:08x}"
    cnonce = os.urandom(8).hex()
    algorithm = (challenge.algorithm or "MD5").upper()

    ha1 = md5(f"{username}:{challenge.realm}:{password}")
    if algorithm == "MD5-SESS":
        ha1 = md5(f"{ha1}:{challenge.nonce}:{cnonce}")
    ha2 = md5(f"{method}:{uri}")

    params = [
        f'username="{username}"',
        f'realm="{challenge.realm}"',
        f'nonce="{challenge.nonce}"',
        f'uri="{uri}"',
    ]
    if challenge.algorithm:
        params.append(f"algorithm={challenge.algorithm}")

    if challenge.qop:
        response = md5(f"{ha1}:{challenge.nonce}:{nc_str}:{cnonce}:{challenge.qop}:{ha2}")
        params += [
            f'response="{response}"',
            f"qop={challenge.qop}",
            f"nc={nc_str}",
            f'cnonce="{cnonce}"',
        ]
    else:
        response = md5(f"{ha1}:{challenge.nonce}:{ha2}")
        params.append(f'response="{response}"')

    if challenge.opaque:
        params.append(f'opaque="{challenge.opaque}"')

    return "Digest " + ", ".join(params)


def _build_basic_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def _pick_challenge(headers: list[str]) -> tuple[str, str] | None:
    """Выбирает схему аутентификации: Digest приоритетнее Basic."""
    basic: tuple[str, str] | None = None
    for header in headers:
        scheme = header.split(" ", 1)[0].lower()
        if scheme == "digest":
            return "digest", header
        if scheme == "basic" and basic is None:
            basic = ("basic", header)
    return basic


async def async_build_auth_header(
    session: aiohttp.ClientSession,
    url: str,
    path: str,
    username: str,
    password: str,
    verify_ssl: bool,
    nc: int = 1,
) -> str | None:
    """Пробный запрос ради 401, затем сборка Authorization под схему устройства.

    Возвращает None, если устройство ответило 200 без аутентификации.
    """
    async with session.get(url, ssl=verify_ssl) as resp:
        await resp.read()
        if resp.status == 200:
            return None
        if resp.status != 401:
            raise RuntimeError(f"Ожидался 401 (auth challenge), получен {resp.status}")
        challenges = list(resp.headers.getall("WWW-Authenticate", []))

    picked = _pick_challenge(challenges)
    if picked is None:
        raise RuntimeError(f"Не нашёл поддерживаемой схемы в WWW-Authenticate: {challenges}")

    scheme, header = picked
    if scheme == "basic":
        return _build_basic_header(username, password)

    challenge = _parse_digest_challenge(header)
    if not challenge.nonce:
        raise RuntimeError("Не удалось разобрать WWW-Authenticate заголовок")
    return _build_digest_header(username, password, "GET", path, challenge, nc=nc)


class HikvisionAlertStreamClient:
    """Держит соединение с терминалом и разбирает поток событий."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        verify_ssl: bool,
        on_event: EventCallback,
        on_connection_change: ConnectionCallback,
    ) -> None:
        self._base_url = f"https://{host}:{port}"
        self._username = username
        self._password = password
        self._verify_ssl = verify_ssl
        self._on_event = on_event
        self._on_connection_change = on_connection_change
        self._task: asyncio.Task | None = None
        self._stopped = False
        self._nc = 0

    def start(self) -> None:
        self._stopped = False
        self._task = asyncio.create_task(self._run_forever())

    async def stop(self) -> None:
        self._stopped = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _run_forever(self) -> None:
        backoff = 2
        while not self._stopped:
            try:
                await self._connect_and_read()
                backoff = 2  # успешное соединение -- сбрасываем backoff
            except asyncio.CancelledError:
                raise
            except AuthFailed as exc:
                _LOGGER.error("Терминал ACS отверг credentials: %s", exc)
                await self._on_connection_change(False, str(exc))
                backoff = 60  # смысла долбить неверным паролем нет
            except Exception as exc:  # noqa: BLE001 -- любой сбой сети/парсинга не должен убивать задачу
                _LOGGER.warning("Обрыв соединения с терминалом ACS: %s", exc)
                await self._on_connection_change(False, str(exc))
            if self._stopped:
                return
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)

    async def _connect_and_read(self) -> None:
        timeout = aiohttp.ClientTimeout(total=None, sock_connect=10, sock_read=70)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            url = f"{self._base_url}{ALERT_STREAM_PATH}"
            self._nc += 1
            auth_header = await async_build_auth_header(
                session,
                url,
                ALERT_STREAM_PATH,
                self._username,
                self._password,
                self._verify_ssl,
                nc=self._nc,
            )

            headers = {"Accept": "multipart/mixed"}
            if auth_header:
                headers["Authorization"] = auth_header

            async with session.get(url, ssl=self._verify_ssl, headers=headers) as resp:
                if resp.status == 401:
                    raise AuthFailed("alertStream вернул 401 с переданными credentials")
                if resp.status != 200:
                    raise RuntimeError(f"alertStream вернул статус {resp.status}")

                boundary = self._parse_boundary(resp.headers.get("Content-Type", ""))
                _LOGGER.info("Соединение с ACS-терминалом установлено")
                await self._on_connection_change(True, None)

                await self._read_multipart(resp, boundary)

    @staticmethod
    def _parse_boundary(content_type: str) -> bytes:
        for part in content_type.split(";"):
            part = part.strip()
            if part.startswith("boundary="):
                value = part[len("boundary="):].strip('"')
                # Hikvision присылает boundary уже с ведущими дефисами
                return value.encode() if value.startswith("--") else ("--" + value).encode()
        raise RuntimeError(f"Не нашёл boundary в Content-Type: {content_type}")

    async def _read_multipart(
        self, resp: aiohttp.ClientResponse, boundary: bytes
    ) -> None:
        buffer = b""
        pending_event: dict | None = None

        async for raw_chunk in resp.content.iter_any():
            buffer += raw_chunk
            if len(buffer) > MAX_BUFFER_BYTES:
                raise RuntimeError(
                    f"Буфер вырос до {len(buffer)} байт без boundary -- поток рассинхронизирован"
                )

            while True:
                start = buffer.find(boundary)
                if start == -1:
                    break
                rest = buffer[start + len(boundary):]
                next_idx = rest.find(boundary)
                if next_idx == -1:
                    break

                part = rest[:next_idx]
                buffer = buffer[start + len(boundary) + next_idx:]

                headers, body = self._split_headers_body(part.strip(b"\r\n-"))
                if not body:
                    continue
                ctype = headers.get("content-type", "")

                if "image/jpeg" in ctype:
                    # JPEG всегда идёт сразу за своим JSON-событием
                    if pending_event is not None:
                        await self._on_event(pending_event, body)
                        pending_event = None
                    continue

                if "application/json" not in ctype and "text" not in ctype:
                    continue

                try:
                    event_json = json.loads(body.decode("utf-8", errors="replace"))
                except json.JSONDecodeError:
                    continue

                # Новый JSON означает, что у предыдущего события фото не будет.
                if pending_event is not None:
                    await self._on_event(pending_event, None)
                    pending_event = None

                if classify_event(event_json) is None:
                    continue  # heartbeat / не-ACS событие -- отдавать нечего
                pending_event = event_json

        # поток закрылся -- если было событие без фото, всё равно отдаём его
        if pending_event is not None:
            await self._on_event(pending_event, None)

    @staticmethod
    def _split_headers_body(chunk: bytes) -> tuple[dict[str, str], bytes]:
        sep = b"\r\n\r\n"
        idx = chunk.find(sep)
        if idx == -1:
            return {}, chunk
        raw_headers, body = chunk[:idx], chunk[idx + len(sep):]
        headers: dict[str, str] = {}
        for line in raw_headers.split(b"\r\n"):
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.strip().lower().decode()] = v.strip().decode()
        return headers, body


def classify_event(event_json: dict) -> tuple[str, dict] | None:
    """Возвращает (event_type, attributes) или None, если это не AccessControllerEvent."""
    acs = event_json.get("AccessControllerEvent")
    if not acs:
        return None
    major = acs.get("majorEventType")
    minor = acs.get("subEventType")
    if major is None or minor is None:
        return None
    major, minor = int(major), int(minor)
    label = EVENT_LABELS.get((major, minor), "unknown_access_event")
    attributes = {
        "major": major,
        "minor": minor,
        "name": acs.get("name") or acs.get("employeeNoString"),
        "employee_no": acs.get("employeeNoString"),
        "card_no": acs.get("cardNo"),
        "verify_mode": acs.get("currentVerifyMode"),
        "device_time": event_json.get("dateTime"),
        "serial_no": acs.get("serialNo"),
    }
    return label, attributes
