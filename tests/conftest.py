"""Загружает модули интеграции без установленного Home Assistant.

`custom_components/hikvision_acs/__init__.py` тянет homeassistant, поэтому
обычный импорт пакета в тестах не сработает. Собираем фиктивный пакет
вручную -- относительные импорты (`from .const import ...`) при этом
разрешаются нормально.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

COMPONENT_DIR = Path(__file__).resolve().parents[1] / "custom_components" / "hikvision_acs"
PKG_NAME = "hik_acs_under_test"


def _load_module(name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(
        f"{PKG_NAME}.{name}", COMPONENT_DIR / f"{name}.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


if PKG_NAME not in sys.modules:
    pkg = types.ModuleType(PKG_NAME)
    pkg.__path__ = [str(COMPONENT_DIR)]
    sys.modules[PKG_NAME] = pkg
    _load_module("const")
    _load_module("alertstream")


@pytest.fixture
def const() -> types.ModuleType:
    return sys.modules[f"{PKG_NAME}.const"]


@pytest.fixture
def alertstream() -> types.ModuleType:
    return sys.modules[f"{PKG_NAME}.alertstream"]
