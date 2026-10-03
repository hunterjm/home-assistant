"""Test configuration for auth."""

from collections.abc import Generator
from unittest.mock import AsyncMock, patch

import pytest

from homeassistant.components.auth.indieauth import ClientInfo

from tests.common import CLIENT_REDIRECT_URI
from tests.typing import ClientSessionGenerator


@pytest.fixture
def mock_client_info() -> Generator[AsyncMock]:
    """Serve an IndieAuth client document for login tests."""
    with patch(
        "homeassistant.components.auth.indieauth._fetch_client_info",
        return_value=ClientInfo([CLIENT_REDIRECT_URI], is_indieauth=True),
    ) as mock:
        yield mock


@pytest.fixture
def aiohttp_client(
    aiohttp_client: ClientSessionGenerator,
    socket_enabled: None,
) -> ClientSessionGenerator:
    """Return aiohttp_client and allow opening sockets."""
    return aiohttp_client
