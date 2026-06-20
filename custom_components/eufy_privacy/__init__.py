"""Integrazione eufy_privacy: setup della config entry."""
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, CONF_COUNTRY, Platform
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import EufyPrivacyCoordinator
from .eufy_cloud import EufyCloudClient
from .push_listener import EufyPushListener
from .services import async_setup_services, async_unload_services

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [
    Platform.SWITCH,
    Platform.BUTTON,
    Platform.BINARY_SENSOR,
    Platform.EVENT,
    Platform.CAMERA,
]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = entry.data
    state = dict(entry.data.get("state", {}))
    state.setdefault("country", data.get(CONF_COUNTRY, "IT"))
    client = EufyCloudClient.from_state(data[CONF_EMAIL], data[CONF_PASSWORD], state)

    coordinator = EufyPrivacyCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    # Cache station (per p2p_did della camera entity) — best effort, non deve bloccare il setup.
    try:
        await hass.async_add_executor_job(coordinator.load_stations)
    except Exception as err:  # noqa: BLE001
        _LOGGER.warning("Caricamento station fallito (camera/thumbnail limitati): %s", err)

    # Listener push per gli eventi — opzionale: un errore non blocca la privacy.
    listener = EufyPushListener(hass, coordinator)
    coordinator.listener = listener
    try:
        await listener.async_start()
    except Exception as err:  # noqa: BLE001
        _LOGGER.warning("Avvio listener push fallito (eventi non disponibili): %s", err)

    await async_setup_services(hass)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    coordinator = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if coordinator is not None and coordinator.listener is not None:
        await coordinator.listener.async_stop()

    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        if not hass.data[DOMAIN]:
            async_unload_services(hass)
    return unloaded
