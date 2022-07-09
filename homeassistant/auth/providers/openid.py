"""OpenID based authentication provider."""
from __future__ import annotations

from collections.abc import Mapping
import logging
from secrets import token_hex
import time
from typing import Any, cast

from aiohttp import ClientResponseError
from aiohttp.client import ClientResponse
import voluptuous as vol

from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.config_entry_oauth2_flow import LocalOAuth2Implementation

from . import AUTH_PROVIDER_SCHEMA, AUTH_PROVIDERS, AuthProvider, LoginFlow
from .. import InvalidAuthError
from ..models import Credentials, RefreshToken, UserMeta

REQUIREMENTS = ["python-jose==3.3.0"]

_LOGGER = logging.getLogger(__name__)

CONF_CONFIGURATION = "configuration"
CONF_EMAILS = "emails"
CONF_SUBJECTS = "subjects"
CONF_FORCE_ACTIVE = "force_active"

CONFIG_SCHEMA = AUTH_PROVIDER_SCHEMA.extend(
    {
        vol.Required(CONF_CONFIGURATION): str,
        vol.Required(CONF_CLIENT_ID): str,
        vol.Required(CONF_CLIENT_SECRET): str,
        vol.Optional(CONF_EMAILS): [str],
        vol.Optional(CONF_SUBJECTS): [str],
        vol.Optional(CONF_FORCE_ACTIVE, default=False): bool,
    },
    extra=vol.PREVENT_EXTRA,
)

OPENID_CONFIGURATION_SCHEMA = vol.Schema(
    {
        vol.Required("issuer"): str,
        vol.Required("jwks_uri"): str,
        vol.Required("id_token_signing_alg_values_supported"): list,
        vol.Optional("scopes_supported"): vol.Contains("openid"),
        vol.Required("token_endpoint"): str,
        vol.Required("authorization_endpoint"): str,
        vol.Required("response_types_supported"): vol.Contains("code"),
        vol.Optional(
            "token_endpoint_auth_methods_supported", default=["client_secret_basic"]
        ): vol.Contains("client_secret_post"),
        vol.Optional(
            "grant_types_supported", default=["authorization_code", "implicit"]
        ): vol.Contains("authorization_code"),
    },
    extra=vol.ALLOW_EXTRA,
)


async def raise_for_status(response: ClientResponse) -> None:
    """Raise exception on data failure with logging."""
    if response.status >= 400:
        standard = ClientResponseError(
            response.request_info,
            response.history,
            code=response.status,
            headers=response.headers,
        )
        data = await response.text()
        _LOGGER.error("Request failed: %s", data)
        raise InvalidAuthError(data) from standard


WANTED_SCOPES = {"openid", "email", "profile"}


class OpenIdLocalOAuth2Implementation(LocalOAuth2Implementation):
    """Local OAuth2 implementation for Toon."""

    _nonce: str | None = None
    _scope: str

    def __init__(
        self,
        hass: HomeAssistant,
        client_id: str,
        client_secret: str,
        configuration: dict[str, Any],
    ) -> None:
        """Initialize local auth implementation."""
        super().__init__(
            hass,
            "auth",
            client_id,
            client_secret,
            configuration["authorization_endpoint"],
            configuration["token_endpoint"],
        )

        self._scope = " ".join(
            sorted(WANTED_SCOPES.intersection(configuration["scopes_supported"]))
        )

    @property
    def extra_authorize_data(self) -> dict[str, Any]:
        """Extra data that needs to be appended to the authorize url."""
        return {"scope": self._scope, "nonce": self._nonce}

    async def async_generate_authorize_url_with_nonce(
        self, flow_id: str, nonce: str
    ) -> str:
        """Generate an authorize url with a given nonce."""
        self._nonce = nonce
        url = await self.async_generate_authorize_url(flow_id)
        self._nonce = None
        return url


@AUTH_PROVIDERS.register("openid")
class OpenIdAuthProvider(AuthProvider):
    """Auth provider using openid connect as the authentication source."""

    DEFAULT_TITLE = "OpenID Connect"

    _configuration: dict[str, Any]
    _jwks: dict[str, Any]
    _oauth2: OpenIdLocalOAuth2Implementation

    async def async_get_configuration(self) -> dict[str, Any]:
        """Get discovery document for OpenID."""
        session = async_get_clientsession(self.hass)
        async with session.get(self.config[CONF_CONFIGURATION]) as response:
            await raise_for_status(response)
            data = await response.json()
        return cast(dict[str, Any], OPENID_CONFIGURATION_SCHEMA(data))

    async def async_get_jwks(self) -> dict[str, Any]:
        """Get the keys for id verification."""
        session = async_get_clientsession(self.hass)
        async with session.get(self._configuration["jwks_uri"]) as response:
            await raise_for_status(response)
            data = await response.json()
        return cast(dict[str, Any], data)

    async def async_login_flow(self, context: dict[str, Any] | None) -> LoginFlow:
        """Return a flow to login."""

        if not hasattr(self, "_configuration"):
            self._configuration = await self.async_get_configuration()

        if not hasattr(self, "_jwks"):
            self._jwks = await self.async_get_jwks()

        self._oauth2 = OpenIdLocalOAuth2Implementation(
            self.hass,
            self.config[CONF_CLIENT_ID],
            self.config[CONF_CLIENT_SECRET],
            self._configuration,
        )

        return OpenIdLoginFlow(self)

    def _decode_id_token(self, token: dict[str, Any], nonce: str) -> dict[str, Any]:
        """Decode openid id_token."""
        # pylint: disable=import-outside-toplevel
        from jose import jwt

        algorithms = self._configuration["id_token_signing_alg_values_supported"]
        issuer = self._configuration["issuer"]

        id_token = cast(
            dict[str, Any],
            jwt.decode(
                token["id_token"],
                algorithms=algorithms,
                issuer=issuer,
                key=self._jwks,
                audience=self.config[CONF_CLIENT_ID],
                access_token=token["access_token"],
            ),
        )
        if id_token.get("nonce") != nonce:
            raise InvalidAuthError("Nonce mismatch in id_token")

        return id_token

    def _authorize_id_token(self, id_token: dict[str, Any]) -> dict[str, Any]:
        """Authorize an id_token according to our internal database."""

        subjects = self.config.get(CONF_SUBJECTS, [])
        emails = self.config.get(CONF_EMAILS, [])

        if not subjects and not emails:
            # No whitelist configured, will create user as inactive unless forced
            return id_token

        if id_token["sub"] in subjects:
            return id_token

        if "email" in id_token and "email_verified" in id_token:
            if id_token["email"] in emails and id_token["email_verified"]:
                return id_token

        raise InvalidAuthError(f"Subject {id_token['sub']} is not allowed")

    async def async_generate_authorize_url_with_nonce(
        self, flow_id: str, nonce: str
    ) -> str:
        """Generate an authorize url with a given nonce."""
        return await self._oauth2.async_generate_authorize_url_with_nonce(
            flow_id, nonce
        )

    async def async_authorize_external_data(
        self, external_data: Any, nonce: str
    ) -> dict[str, Any]:
        """Authorize external data."""
        token = await self._oauth2.async_resolve_external_data(external_data)
        id_token = self._decode_id_token(token, nonce)
        return self._authorize_id_token(id_token)

    @property
    def support_mfa(self) -> bool:
        """Return whether multi-factor auth supported by the auth provider."""
        return False

    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""
        data = cast(dict[str, str], flow_result)
        subject = data["sub"]

        for credential in await self.async_credentials():
            if credential.data["sub"] == subject:
                _LOGGER.info("Accepting credential for %s", subject)
                # Update credential data
                credential.data = data
                return credential

        _LOGGER.info("Creating credential for %s", subject)
        return self.async_create_credentials(data)

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials.

        Will be used to populate info when creating a new user.
        """
        if "name" in credentials.data:
            name = credentials.data["name"]
        elif "given_name" in credentials.data:
            name = credentials.data["given_name"]
            if "family_name" in credentials.data:
                name += f" {credentials.data['family_name']}"
        elif "preferred_username" in credentials.data:
            name = credentials.data["preferred_username"]
        elif "email" in credentials.data:
            name = cast(str, credentials.data["email"]).split("@", 1)[0]
        else:
            name = credentials.data["sub"]

        is_active = (
            self.config[CONF_FORCE_ACTIVE]
            or CONF_SUBJECTS in self.config
            or CONF_EMAILS in self.config
        )

        return UserMeta(name=name, is_active=is_active)

    @callback
    def async_validate_refresh_token(
        self, refresh_token: RefreshToken, remote_ip: str | None = None
    ) -> None:
        """Verify a refresh token is still valid."""
        if (
            refresh_token.credential
            and time.time() > refresh_token.credential.data["exp"]
        ):
            raise InvalidAuthError


class OpenIdLoginFlow(LoginFlow):
    """Handler for the login flow."""

    external_data: Any
    _nonce: str

    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> FlowResult:
        """Handle the step of the form."""
        if user_input is not None:
            return await self.async_step_authenticate()

        return self.async_show_form(step_id="init")

    async def async_step_authenticate(
        self, user_input: dict[str, str] | None = None
    ) -> FlowResult:
        """Authenticate user using external step."""

        provider = cast(OpenIdAuthProvider, self._auth_provider)

        if user_input:
            self.external_data = user_input
            return self.async_external_step_done(next_step_id="authorize")

        self._nonce = token_hex()
        url = await provider.async_generate_authorize_url_with_nonce(
            self.flow_id, self._nonce
        )
        return self.async_external_step(step_id="authenticate", url=url)

    async def async_step_authorize(
        self, user_input: dict[str, str] | None = None
    ) -> FlowResult:
        """Authorize user received from external step."""

        provider = cast(OpenIdAuthProvider, self._auth_provider)
        try:
            result = await provider.async_authorize_external_data(
                self.external_data, self._nonce
            )
        except InvalidAuthError as error:
            _LOGGER.error("Login failed: %s", str(error))
            return self.async_abort(reason="invalid_auth")
        return await self.async_finish(result)
