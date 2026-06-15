"""Eufy Privacy integration."""
from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ConfigEntryNotReady, HomeAssistantError
from homeassistant.helpers import aiohttp_client
import homeassistant.helpers.config_validation as cv

from .bridge import BridgeAuthError, BridgeClient, BridgeError, BridgeUnreachable
from .const import (
    ATTR_ENABLED,
    ATTR_SERIAL,
    CONF_BRIDGE_TOKEN,
    CONF_BRIDGE_URL,
    CONF_COUNTRY,
    CONF_EMAIL,
    CONF_LANGUAGE,
    CONF_PASSWORD,
    DOMAIN,
    PLATFORMS,
    SERVICE_SET_PRIVACY_MODE,
)
from .coordinator import EufyCoordinator
from .events import EufyEventStream

_LOGGER = logging.getLogger(__name__)


SET_PRIVACY_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_SERIAL): cv.string,
        vol.Required(ATTR_ENABLED): cv.boolean,
    }
)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    session = aiohttp_client.async_get_clientsession(hass)
    bridge = BridgeClient(
        session,
        entry.data[CONF_BRIDGE_URL],
        entry.data.get(CONF_BRIDGE_TOKEN),
    )

    credentials = {
        CONF_EMAIL: entry.data[CONF_EMAIL],
        CONF_PASSWORD: entry.data[CONF_PASSWORD],
        CONF_COUNTRY: entry.data[CONF_COUNTRY],
        CONF_LANGUAGE: entry.data[CONF_LANGUAGE],
    }

    try:
        await bridge.init(
            email=credentials[CONF_EMAIL],
            password=credentials[CONF_PASSWORD],
            country=credentials[CONF_COUNTRY],
            language=credentials[CONF_LANGUAGE],
        )
    except BridgeUnreachable as err:
        raise ConfigEntryNotReady(f"Bridge not reachable: {err}") from err
    except BridgeAuthError as err:
        # Credenziali non valide più / 2FA / CAPTCHA: lasciamo HA marcare reauth
        raise ConfigEntryNotReady(f"Eufy auth failed: {err}") from err

    coordinator = EufyCoordinator(hass, bridge, credentials)
    await coordinator.async_config_entry_first_refresh()

    stream = EufyEventStream(bridge, coordinator)
    stream.start(hass, entry)

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "coordinator": coordinator,
        "stream": stream,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    _register_services(hass)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        entry_data = hass.data[DOMAIN].pop(entry.entry_id, None)
        if entry_data is not None:
            await entry_data["stream"].stop()
        if not hass.data[DOMAIN]:
            hass.services.async_remove(DOMAIN, SERVICE_SET_PRIVACY_MODE)
    return unload_ok


def _register_services(hass: HomeAssistant) -> None:
    if hass.services.has_service(DOMAIN, SERVICE_SET_PRIVACY_MODE):
        return

    async def _handle_set_privacy(call: ServiceCall) -> None:
        serial = call.data[ATTR_SERIAL]
        enabled = call.data[ATTR_ENABLED]
        entries: list[dict] = list(hass.data.get(DOMAIN, {}).values())
        if not entries:
            raise HomeAssistantError("eufy_privacy: no configured entry")
        coordinators: list[EufyCoordinator] = [e["coordinator"] for e in entries]
        target = next(
            (c for c in coordinators if serial in (c.data or {})),
            coordinators[0],
        )
        try:
            await target.async_set_privacy(serial, enabled)
        except BridgeError as err:
            raise HomeAssistantError(f"Bridge call failed: {err}") from err

    hass.services.async_register(
        DOMAIN,
        SERVICE_SET_PRIVACY_MODE,
        _handle_set_privacy,
        schema=SET_PRIVACY_SCHEMA,
    )
