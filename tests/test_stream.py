"""Тесты разбора multipart/mixed потока alertStream и классификации событий."""
from __future__ import annotations

import asyncio

import pytest

BOUNDARY = b"--MIME_boundary"

JPEG = b"\xff\xd8\xff\xe0fake-jpeg-bytes\xff\xd9"


def _json_part(payload: str) -> bytes:
    body = payload.encode()
    return (
        BOUNDARY + b"\r\n"
        b"Content-Type: application/json; charset=utf-8\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body + b"\r\n"
    )


def _image_part(body: bytes = JPEG) -> bytes:
    return (
        BOUNDARY + b"\r\n"
        b"Content-Type: image/jpeg\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body + b"\r\n"
    )


def _acs_event(minor: int, name: str = "Иван", serial: int = 1) -> str:
    return (
        '{"ipAddress":"192.168.1.64","dateTime":"2026-09-17T22:30:00+03:00",'
        '"eventType":"AccessControllerEvent","AccessControllerEvent":'
        f'{{"majorEventType":5,"subEventType":{minor},"name":"{name}",'
        f'"employeeNoString":"42","currentVerifyMode":"cardOrFaceOrFp","serialNo":{serial}}}}}'
    )


HEARTBEAT = (
    '{"ipAddress":"192.168.1.64","dateTime":"2026-09-17T22:30:05+03:00",'
    '"eventType":"videoloss","eventState":"inactive","eventDescription":"videoloss alarm"}'
)

# Реальный payload с DS-K1T342MFWX: терминал пишет в журнал факт
# подключения ISAPI-клиента. majorEventType=3 -- MAJOR_OPERATION, не проход.
OPERATION_EVENT = (
    '{"ipAddress":"192.168.7.104","portNo":443,"protocol":"HTTPS",'
    '"dateTime":"2026-09-18T10:05:16+03:00","activePostCount":1,'
    '"eventType":"AccessControllerEvent","eventState":"active",'
    '"eventDescription":"Access Controller Event","AccessControllerEvent":'
    '{"deviceName":"Access Controller","majorEventType":3,"subEventType":121,'
    '"remoteHostAddr":"192.168.7.110","serialNo":59091,"currentEvent":false,'
    '"frontSerialNo":59090,"label":"","purePwdVerifyEnable":true}}'
)


class _FakeContent:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def iter_any(self):
        for chunk in self._chunks:
            yield chunk


class _FakeResponse:
    def __init__(self, chunks: list[bytes]) -> None:
        self.content = _FakeContent(chunks)


def _client(alertstream, collected: list):
    async def on_event(event_json, photo):
        collected.append((event_json, photo))

    async def on_conn(connected, error):
        pass

    return alertstream.HikvisionAlertStreamClient(
        host="192.168.1.64",
        port=443,
        username="u",
        password="p",
        verify_ssl=False,
        on_event=on_event,
        on_connection_change=on_conn,
    )


def _read(alertstream, chunks: list[bytes]) -> list:
    collected: list = []
    client = _client(alertstream, collected)
    asyncio.run(client._read_multipart(_FakeResponse(chunks), BOUNDARY))
    return collected


# --- boundary -------------------------------------------------------------


def test_parse_boundary_variants(alertstream):
    parse = alertstream.HikvisionAlertStreamClient._parse_boundary
    assert parse("multipart/mixed; boundary=MIME_boundary") == b"--MIME_boundary"
    assert parse('multipart/mixed; boundary="--MIME_boundary"') == b"--MIME_boundary"
    with pytest.raises(RuntimeError):
        parse("text/plain")


# --- разбор потока --------------------------------------------------------


def test_event_with_photo_paired(alertstream):
    stream = _json_part(_acs_event(75)) + _image_part() + _json_part(HEARTBEAT) + BOUNDARY
    events = _read(alertstream, [stream])
    assert len(events) == 1
    event_json, photo = events[0]
    assert photo == JPEG
    assert event_json["AccessControllerEvent"]["subEventType"] == 75


def test_event_without_photo_is_not_swallowed(alertstream):
    """Событие без JPEG раньше терялось, если следом шло другое событие."""
    stream = (
        _json_part(_acs_event(27, serial=1))
        + _json_part(_acs_event(27, serial=2))
        + BOUNDARY
    )
    events = _read(alertstream, [stream])
    assert [photo for _, photo in events] == [None, None]
    assert [e["AccessControllerEvent"]["serialNo"] for e, _ in events] == [1, 2]


def test_heartbeat_flushes_pending_event(alertstream):
    """Keep-alive между событиями обязан вытолкнуть предыдущее событие без фото."""
    stream = _json_part(_acs_event(38)) + _json_part(HEARTBEAT) + BOUNDARY
    events = _read(alertstream, [stream])
    assert len(events) == 1
    assert events[0][1] is None


def test_heartbeat_alone_yields_nothing(alertstream):
    events = _read(alertstream, [_json_part(HEARTBEAT) + _json_part(HEARTBEAT) + BOUNDARY])
    assert events == []


def test_last_event_flushed_on_stream_close(alertstream):
    events = _read(alertstream, [_json_part(_acs_event(75)) + BOUNDARY])
    assert len(events) == 1
    assert events[0][1] is None


def test_parts_split_across_tcp_chunks(alertstream):
    stream = _json_part(_acs_event(75)) + _image_part() + BOUNDARY
    chunks = [stream[i : i + 7] for i in range(0, len(stream), 7)]
    events = _read(alertstream, chunks)
    assert len(events) == 1
    assert events[0][1] == JPEG


def test_malformed_json_skipped(alertstream):
    stream = _json_part("{not json") + _json_part(_acs_event(75)) + _image_part() + BOUNDARY
    events = _read(alertstream, [stream])
    assert len(events) == 1
    assert events[0][1] == JPEG


def test_runaway_buffer_forces_reconnect(alertstream, const):
    junk = b"x" * (const.MAX_BUFFER_BYTES + 1)
    with pytest.raises(RuntimeError, match="рассинхронизирован"):
        _read(alertstream, [junk])


# --- classify_event -------------------------------------------------------


def test_classify_known_event(alertstream):
    import json

    label, attrs = alertstream.classify_event(json.loads(_acs_event(75)))
    assert label == "face_authenticated"
    assert attrs["name"] == "Иван"
    assert attrs["employee_no"] == "42"
    assert attrs["serial_no"] == 1
    assert attrs["device_time"] == "2026-09-17T22:30:00+03:00"


def test_classify_unknown_code(alertstream):
    import json

    label, attrs = alertstream.classify_event(json.loads(_acs_event(9999)))
    assert label == "unknown_access_event"
    assert (attrs["major"], attrs["minor"]) == (5, 9999)


def test_classify_ignores_non_acs(alertstream):
    import json

    assert alertstream.classify_event(json.loads(HEARTBEAT)) is None
    assert alertstream.classify_event({"AccessControllerEvent": {"name": "x"}}) is None


def test_classify_ignores_operation_events(alertstream):
    """major=3 (MAJOR_OPERATION) -- запись о подключении клиента, не проход."""
    import json

    assert alertstream.classify_event(json.loads(OPERATION_EVENT)) is None


def test_operation_events_produce_no_ha_events(alertstream):
    """Из-за них event.* дёргался на каждый реконнект HA."""
    stream = _json_part(OPERATION_EVENT) + _json_part(HEARTBEAT) + BOUNDARY
    assert _read(alertstream, [stream]) == []


def test_replayed_event_deduplicated_by_serial(alertstream):
    """При переподключении терминал заново отдаёт последние записи журнала."""
    stream = (
        _json_part(_acs_event(75, serial=100))
        + _json_part(_acs_event(75, serial=100))
        + _json_part(_acs_event(75, serial=101))
        + BOUNDARY
    )
    events = _read(alertstream, [stream])
    assert [e["AccessControllerEvent"]["serialNo"] for e, _ in events] == [100, 101]


def test_classify_exposes_is_current(alertstream):
    import json

    payload = json.loads(_acs_event(75))
    payload["AccessControllerEvent"]["currentEvent"] = False
    _, attrs = alertstream.classify_event(payload)
    assert attrs["is_current"] is False


def test_all_labels_are_in_event_types(const):
    for label in const.EVENT_LABELS.values():
        assert label in const.ALL_EVENT_TYPES
    assert "unknown_access_event" in const.ALL_EVENT_TYPES
