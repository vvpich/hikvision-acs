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
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import aiohttp

from .const import (
    ALERT_STREAM_PATH,
    EVENT_LABELS,
    MAJOR_EVENT,
    MAX_BUFFER_BYTES,
    SEEN_SERIALS_MEMORY,
    SUBSCRIBE_EVENT_CANDIDATES,
    SUBSCRIBE_EVENT_PATH,
    SUBSCRIBE_TIMEOUT,
)

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


def _auth_header_from_challenges(
    challenges: list[str],
    username: str,
    password: str,
    method: str,
    path: str,
    nc: int,
) -> str:
    picked = _pick_challenge(challenges)
    if picked is None:
        raise RuntimeError(f"Не нашёл поддерживаемой схемы в WWW-Authenticate: {challenges}")

    scheme, header = picked
    if scheme == "basic":
        return _build_basic_header(username, password)

    challenge = _parse_digest_challenge(header)
    if not challenge.nonce:
        raise RuntimeError("Не удалось разобрать WWW-Authenticate заголовок")
    return _build_digest_header(username, password, method, path, challenge, nc=nc)


async def async_build_auth_header(
    session: aiohttp.ClientSession,
    url: str,
    path: str,
    username: str,
    password: str,
    verify_ssl: bool,
    nc: int = 1,
    method: str = "GET",
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

    return _auth_header_from_challenges(
        challenges, username, password, method, path, nc
    )


async def async_isapi_request(
    session: aiohttp.ClientSession,
    method: str,
    base_url: str,
    path: str,
    username: str,
    password: str,
    verify_ssl: bool,
    data: str | None = None,
    content_type: str | None = None,
) -> tuple[int, str]:
    """Запрос к ISAPI с аутентификацией по челленджу устройства.

    Digest считается для того же метода, которым уйдёт тело, поэтому
    challenge берём тем же методом, а не GET'ом.
    """
    url = f"{base_url}{path}"
    headers: dict[str, str] = {}
    if content_type:
        headers["Content-Type"] = content_type

    async with session.request(
        method, url, ssl=verify_ssl, data=data, headers=headers
    ) as resp:
        if resp.status != 401:
            return resp.status, await resp.text()
        challenges = list(resp.headers.getall("WWW-Authenticate", []))
        await resp.read()

    headers["Authorization"] = _auth_header_from_challenges(
        challenges, username, password, method, path, nc=1
    )
    async with session.request(
        method, url, ssl=verify_ssl, data=data, headers=headers
    ) as resp:
        return resp.status, await resp.text()


async def async_fetch_json(
    session: aiohttp.ClientSession,
    base_url: str,
    path: str,
    username: str,
    password: str,
    verify_ssl: bool,
) -> dict:
    """GET одного ISAPI-ресурса с той же схемой аутентификации, что и поток."""
    url = f"{base_url}{path}"
    auth_header = await async_build_auth_header(
        session, url, path, username, password, verify_ssl
    )
    headers = {"Authorization": auth_header} if auth_header else {}
    async with session.get(url, ssl=verify_ssl, headers=headers) as resp:
        if resp.status == 401:
            raise AuthFailed(f"{path} вернул 401 с переданными credentials")
        resp.raise_for_status()
        # Терминал отдаёт JSON с Content-Type application/json, но не всегда
        return await resp.json(content_type=None)


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
        subscribe_pictures: bool = False,
    ) -> None:
        self._base_url = f"https://{host}:{port}"
        self._username = username
        self._password = password
        self._verify_ssl = verify_ssl
        self._on_event = on_event
        self._on_connection_change = on_connection_change
        self._subscribe_pictures = subscribe_pictures
        self._task: asyncio.Task | None = None
        self._stopped = False
        self._nc = 0
        self._seen_serials: deque[int] = deque(maxlen=SEEN_SERIALS_MEMORY)
        self._subscribe_attempt = 0

    def _is_duplicate(self, event_json: dict) -> bool:
        """Терминал переотдаёт последние записи журнала при переподключении."""
        serial = event_json.get("AccessControllerEvent", {}).get("serialNo")
        if serial is None:
            return False
        if serial in self._seen_serials:
            _LOGGER.debug("Повтор события serialNo=%s -- пропускаю", serial)
            return True
        self._seen_serials.append(serial)
        return False

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

    async def _async_subscribe(self, session: aiohttp.ClientSession) -> None:
        """Подписка с pictureURLType=binary: попытка получить фото в потоке.

        По умолчанию выключена (CONF_SUBSCRIBE_PICTURES): на V4.38.0
        DS-K1T342MFWX ни один вариант XML не принят, а сами POST'ы
        отъедают слот deploy, из-за чего alertStream остаётся без слота и
        события перестают приходить вовсе.

        Оформляется ДО открытия alertStream: подписка и поток делят один
        лимит "deploy", и при уже открытом потоке устройство отвечает
        deployExceedMax. Неподдерживающие прошивки просто вернут ошибку --
        для них поток работает как раньше, без фото.
        """
        # Одна попытка на соединение: POST подписки, похоже, тоже занимает
        # слот deploy, и серия попыток подряд оставляет alertStream без слота.
        if not self._subscribe_pictures:
            return

        name, xml = SUBSCRIBE_EVENT_CANDIDATES[
            self._subscribe_attempt % len(SUBSCRIBE_EVENT_CANDIDATES)
        ]
        self._subscribe_attempt += 1

        try:
            async with asyncio.timeout(SUBSCRIBE_TIMEOUT):
                status, body = await async_isapi_request(
                    session,
                    "POST",
                    self._base_url,
                    SUBSCRIBE_EVENT_PATH,
                    self._username,
                    self._password,
                    self._verify_ssl,
                    data=xml,
                    content_type="application/xml",
                )
        except Exception as exc:  # noqa: BLE001 -- подписка не критична для потока
            _LOGGER.debug("Подписка (%s) не удалась: %s", name, exc)
            return

        if status == 200 and "<statusString>OK</statusString>" in body:
            _LOGGER.info("Подписка на события оформлена (%s, pictureURLType=binary)", name)
        else:
            _LOGGER.debug(
                "Устройство отклонило подписку (%s, HTTP %s): %s",
                name,
                status,
                " ".join(body.split())[:300],
            )

    async def _connect_and_read(self) -> None:
        timeout = aiohttp.ClientTimeout(total=None, sock_connect=10, sock_read=70)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            await self._async_subscribe(session)

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
                    _LOGGER.debug("JPEG из потока, %d байт", len(body))
                    if pending_event is not None:
                        await self._on_event(pending_event, body)
                        pending_event = None
                    else:
                        _LOGGER.debug("JPEG пришёл без предшествующего события -- отбрасываю")
                    continue

                if "application/json" not in ctype and "text" not in ctype:
                    _LOGGER.debug("Часть потока с неизвестным Content-Type %r", ctype)
                    continue

                raw = body.decode("utf-8", errors="replace")
                try:
                    event_json = json.loads(raw)
                except json.JSONDecodeError:
                    _LOGGER.debug("Часть потока не разобралась как JSON: %r", raw[:500])
                    continue
                _LOGGER.debug("JSON из потока: %s", raw)

                # Новый JSON означает, что у предыдущего события фото не будет.
                if pending_event is not None:
                    await self._on_event(pending_event, None)
                    pending_event = None

                classified = classify_event(event_json)
                if classified is None:
                    continue  # heartbeat / не событие доступа -- отдавать нечего
                if self._is_duplicate(event_json):
                    continue
                _LOGGER.debug(
                    "Событие %s (major=%s minor=%s)",
                    classified[0],
                    classified[1]["major"],
                    classified[1]["minor"],
                )
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
    """Возвращает (event_type, attributes) или None, если это не событие доступа.

    Отсеиваются keep-alive, не-ACS события и все категории majorEventType
    кроме MAJOR_EVENT: тревоги, неисправности и операции с устройством
    авторизациями не являются.
    """
    acs = event_json.get("AccessControllerEvent")
    if not acs:
        return None
    major = acs.get("majorEventType")
    minor = acs.get("subEventType")
    if major is None or minor is None:
        return None
    major, minor = int(major), int(minor)
    if major != MAJOR_EVENT:
        _LOGGER.debug(
            "Пропускаю не-событие доступа: major=%s minor=%s (%s)",
            major,
            minor,
            event_json.get("eventDescription"),
        )
        return None
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
        # false => запись из журнала терминала, а не происходящее сейчас
        "is_current": acs.get("currentEvent"),
    }
    return label, attributes
