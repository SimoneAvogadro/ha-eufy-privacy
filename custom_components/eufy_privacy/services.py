"""Servizio `eufy_privacy.take_snapshot`: salva un frame FRESCO (P2P) di una camera su file.

Pensato per ha-tasker (che chiama servizi HA): target = entity_id della camera + filename.
Schema speculare a `camera.snapshot`. Rispetta l'allowlist (allowlist_external_dirs).
"""
from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv, entity_registry as er
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .const import DOMAIN, SIGNAL_IMAGE

_LOGGER = logging.getLogger(__name__)

SERVICE_TAKE_SNAPSHOT = "take_snapshot"
_SUFFIX = "_camera"

SERVICE_SCHEMA = vol.Schema({
    vol.Required("entity_id"): cv.entity_id,
    vol.Required("filename"): cv.template,
})


def _find_camera(hass: HomeAssistant, serial: str):
    """Trova (coordinator, EufyCamera) per il serial fra tutte le config entry."""
    for coordinator in hass.data.get(DOMAIN, {}).values():
        cam = coordinator.data.get(serial)
        if cam is not None:
            return coordinator, cam
    return None, None


def _write_bytes(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


async def async_setup_services(hass: HomeAssistant) -> None:
    if hass.services.has_service(DOMAIN, SERVICE_TAKE_SNAPSHOT):
        return

    async def _handle_take_snapshot(call: ServiceCall) -> None:
        entity_id = call.data["entity_id"]
        ent = er.async_get(hass).async_get(entity_id)
        if ent is None or ent.platform != DOMAIN or not ent.unique_id.endswith(_SUFFIX):
            raise HomeAssistantError(f"{entity_id} non e' una camera eufy_privacy")
        serial = ent.unique_id[: -len(_SUFFIX)]
        coordinator, cam = _find_camera(hass, serial)
        if cam is None:
            raise HomeAssistantError(f"Camera {serial} non trovata")

        filename = call.data["filename"]
        filename.hass = hass
        path = filename.async_render(variables={"entity_id": entity_id})
        if not hass.config.is_allowed_path(path):
            raise HomeAssistantError(f"Percorso non consentito (allowlist_external_dirs): {path}")

        image = await hass.async_add_executor_job(coordinator.client.grab_snapshot_p2p, cam)
        await hass.async_add_executor_job(_write_bytes, path, image)
        async_dispatcher_send(hass, SIGNAL_IMAGE.format(serial=serial), image)
        _LOGGER.info("Snapshot di %s salvato in %s (%d byte)", serial, path, len(image))

    hass.services.async_register(
        DOMAIN, SERVICE_TAKE_SNAPSHOT, _handle_take_snapshot, schema=SERVICE_SCHEMA
    )


@callback
def async_unload_services(hass: HomeAssistant) -> None:
    if hass.services.has_service(DOMAIN, SERVICE_TAKE_SNAPSHOT):
        hass.services.async_remove(DOMAIN, SERVICE_TAKE_SNAPSHOT)
