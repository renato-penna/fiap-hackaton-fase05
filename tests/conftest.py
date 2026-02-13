"""Fixtures compartilhadas para testes."""

import sys
from pathlib import Path

import pytest

# Garante que o root do projeto está no path para imports
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.stride.categories import CategoryClassifier  # noqa: E402
from src.stride.engine import StrideEngine  # noqa: E402


@pytest.fixture
def classifier() -> CategoryClassifier:
    return CategoryClassifier()


@pytest.fixture
def stride_engine() -> StrideEngine:
    return StrideEngine()
