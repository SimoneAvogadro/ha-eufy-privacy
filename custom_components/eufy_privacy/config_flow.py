"""Config flow for the Eufy Privacy integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers import aiohttp_client

from .bridge import BridgeAuthError, BridgeClient, BridgeError, BridgeUnreachable
from .const import (
    CONF_BRIDGE_TOKEN,
    CONF_BRIDGE_URL,
    CONF_COUNTRY,
    CONF_EMAIL,
    CONF_LANGUAGE,
    CONF_PASSWORD,
    DEFAULT_BRIDGE_URL,
    DEFAULT_COUNTRY,
    DEFAULT_LANGUAGE,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


def _user_schema(defaults: dict[str, Any] | None = None) -> vol.Schema:
    d = defaults or {}
    return vol.Schema(
        {
            vol.Required(CONF_EMAIL, default=d.get(CONF_EMAIL, "")): str,
            vol.Required(CONF_PASSWORD): str,
            vol.Required(CONF_COUNTRY, default=d.get(CONF_COUNTRY, DEFAULT_COUNTRY)): str,
            vol.Required(CONF_LANGUAGE, default=d.get(CONF_LANGUAGE, DEFAULT_LANGUAGE)): str,
            vol.Required(CONF_BRIDGE_URL, default=d.get(CONF_BRIDGE_URL, DEFAULT_BRIDGE_URL)): str,
            vol.Optional(CONF_BRIDGE_TOKEN, default=d.get(CONF_BRIDGE_TOKEN, "")): str,
        }
    )


class EufyPrivacyConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Eufy Privacy."""

    VERSION = 1

    async def async_step_user(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            # Una sola istanza
            await self.async_set_unique_id(user_input[CONF_EMAIL].lower())
            self._abort_if_unique_id_configured()

            session = aiohttp_client.async_get_clientsession(self.hass)
            bridge = BridgeClient(
                session,
                user_input[CONF_BRIDGE_URL],
                user_input.get(CONF_BRIDGE_TOKEN) or None,
            )

            try:
                await bridge.init(
                    email=user_input[CONF_EMAIL],
                    password=user_input[CONF_PASSWORD],
                    country=user_input[CONF_COUNTRY],
                    language=user_input[CONF_LANGUAGE],
                )
            except BridgeUnreachable:
                errors["base"] = "bridge_unreachable"
            except BridgeAuthError as err:
                if err.code == "CAPTCHA":
                    errors["base"] = "captcha_required"
                elif err.code == "2FA":
                    errors["base"] = "two_factor_required"
                elif err.code == "BRIDGE_AUTH":
                    errors[CONF_BRIDGE_TOKEN] = "bridge_token_invalid"
                else:
                    errors["base"] = "invalid_auth"
            except BridgeError as err:
                _LOGGER.exception("Unexpected bridge error: %s", err)
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(
                    title=user_input[CONF_EMAIL],
                    data=user_input,
                )

        return self.async_show_form(
            step_id="user",
            data_schema=_user_schema(user_input),
            errors=errors,
        )
