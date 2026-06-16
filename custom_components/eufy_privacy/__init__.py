"""Integrazione eufy_privacy: setup della config entry."""
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, CONF_COUNTRY, Platform
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import EufyPrivacyCoordinator
from .eufy_cloud import EufyCloudClient

PLATFORMS = [Platform.SWITCH, Platform.BUTTON]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = entry.data
    state = dict(entry.data.get("state", {}))
    state.setdefault("country", data.get(CONF_COUNTRY, "IT"))
    client = EufyCloudClient.from_state(data[CONF_EMAIL], data[CONF_PASSWORD], state)

    coordinator = EufyPrivacyCoordinator(hass, client)
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # persisti eventuale token rinnovato
    new_state = await hass.async_add_executor_job(client.export_state)
    if new_state != data.get("state"):
        hass.config_entries.async_update_entry(
            entry, data={**data, "state": new_state}
        )
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unloaded
