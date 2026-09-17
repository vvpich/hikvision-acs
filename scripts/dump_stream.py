#!/usr/bin/env python3
"""Диагностика: печатает всё, что терминал присылает в alertStream.

Home Assistant для запуска не нужен -- только aiohttp. Показывает каждую
часть multipart-потока: Content-Type, размер, JSON целиком (или размер
JPEG), и то, как интеграция классифицировала бы событие. Нужен, чтобы
понять, какие major/minor реально шлёт конкретная прошивка, и приходят ли
фото вообще.

    python scripts/dump_stream.py 192.168.1.64 --user hass --password 'secret'

Пароль можно передать через переменную окружения HIK_PASSWORD.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import os
import sys
import types
from datetime import datetime
from pathlib import Path

import aiohttp

COMPONENT_DIR = Path(__file__).resolve().parents[1] / "custom_components" / "hikvision_acs"
PKG_NAME = "hik_acs_dump"


def _load_component() -> tuple[types.ModuleType, types.ModuleType]:
    """Импортирует const/alertstream без пакетного __init__ (тот тянет HA)."""
    pkg = types.ModuleType(PKG_NAME)
    pkg.__path__ = [str(COMPONENT_DIR)]
    sys.modules[PKG_NAME] = pkg

    loaded = {}
    for name in ("const", "alertstream"):
        spec = importlib.util.spec_from_file_location(
            f"{PKG_NAME}.{name}", COMPONENT_DIR / f"{name}.py"
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        loaded[name] = module
    return loaded["const"], loaded["alertstream"]


const, alertstream = _load_component()


def _stamp() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


async def dump(args: argparse.Namespace) -> int:
    password = args.password or os.environ.get("HIK_PASSWORD")
    if not password:
        print("Нужен --password или переменная окружения HIK_PASSWORD", file=sys.stderr)
        return 2

    url = f"https://{args.host}:{args.port}{const.ALERT_STREAM_PATH}"
    timeout = aiohttp.ClientTimeout(total=None, sock_connect=10, sock_read=args.read_timeout)
    parts = jsons = images = acs_events = 0

    async with aiohttp.ClientSession(timeout=timeout) as session:
        auth_header = await alertstream.async_build_auth_header(
            session, url, const.ALERT_STREAM_PATH, args.user, password, False
        )
        print(f"[{_stamp()}] auth: {auth_header.split(' ')[0] if auth_header else 'не требуется'}")

        headers = {"Accept": "multipart/mixed"}
        if auth_header:
            headers["Authorization"] = auth_header

        async with session.get(url, ssl=False, headers=headers) as resp:
            print(f"[{_stamp()}] HTTP {resp.status}, Content-Type: {resp.headers.get('Content-Type')}")
            if resp.status != 200:
                print(await resp.text())
                return 1

            boundary = alertstream.HikvisionAlertStreamClient._parse_boundary(
                resp.headers.get("Content-Type", "")
            )
            print(f"[{_stamp()}] boundary: {boundary!r}. Ctrl-C для выхода.\n")

            buffer = b""
            async for chunk in resp.content.iter_any():
                buffer += chunk
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

                    part_headers, body = alertstream.HikvisionAlertStreamClient._split_headers_body(
                        part.strip(b"\r\n-")
                    )
                    if not body:
                        continue
                    parts += 1
                    ctype = part_headers.get("content-type", "?")

                    if "image/jpeg" in ctype:
                        images += 1
                        print(f"[{_stamp()}] JPEG, {len(body)} байт")
                        if args.save_images:
                            path = Path(args.save_images) / f"acs_{images:04d}.jpg"
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.write_bytes(body)
                            print(f"           -> {path}")
                        continue

                    jsons += 1
                    raw = body.decode("utf-8", errors="replace")
                    try:
                        payload = json.loads(raw)
                    except json.JSONDecodeError:
                        print(f"[{_stamp()}] не-JSON ({ctype}): {raw[:300]!r}")
                        continue

                    classified = alertstream.classify_event(payload)
                    if classified is None:
                        acs = payload.get("AccessControllerEvent")
                        kind = payload.get("eventType", "?")
                        if args.all:
                            print(f"[{_stamp()}] игнор: eventType={kind} acs={bool(acs)} {raw}")
                        else:
                            print(f"[{_stamp()}] игнор: eventType={kind}")
                        continue

                    acs_events += 1
                    label, attrs = classified
                    print(
                        f"[{_stamp()}] СОБЫТИЕ {label} major={attrs['major']} "
                        f"minor={attrs['minor']} name={attrs['name']!r} "
                        f"employee={attrs['employee_no']!r} card={attrs['card_no']!r} "
                        f"verify={attrs['verify_mode']!r}"
                    )
                    print(f"           raw: {raw}")

    print(f"\nитого: частей={parts} json={jsons} jpeg={images} событий={acs_events}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=const.DEFAULT_PORT)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", help="или переменная окружения HIK_PASSWORD")
    parser.add_argument("--all", action="store_true", help="печатать сырой JSON и для игнорируемых частей")
    parser.add_argument("--save-images", metavar="DIR", help="сохранять пришедшие JPEG в каталог")
    parser.add_argument("--read-timeout", type=int, default=70, help="сек без данных до обрыва")
    args = parser.parse_args()

    try:
        return asyncio.run(dump(args))
    except KeyboardInterrupt:
        print("\nостановлено")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
