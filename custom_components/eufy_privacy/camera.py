"""Camera entity per ogni cam: mostra l'ultima immagine (thumbnail evento o snapshot fresco).

L'immagine NON e' uno stream: e' una cache di byte aggiornata da (a) gli eventi push che
portano un pic_url (scaricato + decifrato con decode_image) e (b) il servizio take_snapshot
(frame fresco via P2P, ricevuto su SIGNAL_IMAGE). Niente live-view (fuori scope).
"""
from __future__ import annotations

import logging

from homeassistant.components.camera import Camera
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, SIGNAL_EVENT, SIGNAL_IMAGE

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(EufyEventCamera(coordinator, serial) for serial in coordinator.data)


class EufyEventCamera(Camera):
    _attr_has_entity_name = True
    _attr_name = None  # usa il nome del device

    def __init__(self, coordinator, serial: str) -> None:
        Camera.__init__(self)
        self.coordinator = coordinator
        self._serial = serial
        self._attr_unique_id = f"{serial}_camera"
        self._image: bytes | None = None

    @property
    def device_info(self) -> DeviceInfo:
        cam = self.coordinator.data.get(self._serial)
        return DeviceInfo(
            identifiers={(DOMAIN, self._serial)},
            name=cam.name if cam else self._serial,
            manufacturer="Eufy",
            model=cam.model if cam else None,
        )

    async def async_camera_image(self, width=None, height=None) -> bytes | None:
        return self._image

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, SIGNAL_EVENT.format(serial=self._serial), self._handle_event
            )
        )
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, SIGNAL_IMAGE.format(serial=self._serial), self._handle_image
            )
        )

    @callback
    def _handle_event(self, event) -> None:
        if event.pic_url:
            self.hass.async_create_task(self._async_update_from_url(event.pic_url))

    async def _async_update_from_url(self, pic_url: str) -> None:
        cam = self.coordinator.data.get(self._serial)
        p2p_did = self.coordinator.p2p_did_for(cam) if cam else None
        if p2p_did is None:
            # cache station mancante/obsoleta: prova a ricaricarla una volta
            await self.hass.async_add_executor_job(self.coordinator.load_stations)
            p2p_did = self.coordinator.p2p_did_for(cam) if cam else None
        if p2p_did is None:
            _LOGGER.debug("p2p_did assente per %s: salto l'aggiornamento thumbnail", self._serial)
            return
        try:
            image = await self.hass.async_add_executor_job(
                self.coordinator.client.get_event_image, pic_url, p2p_did
            )
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Download thumbnail fallito per %s: %s", self._serial, err)
            return
        self._image = image
        self.async_write_ha_state()

    @callback
    def _handle_image(self, image: bytes) -> None:
        self._image = image
        self.async_write_ha_state()
