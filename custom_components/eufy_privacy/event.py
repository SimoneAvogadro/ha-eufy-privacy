"""Entita' `event` per camera: registra l'ultimo evento push (tipo + attributi).

Usa l'API nativa EventEntity (_trigger_event), niente evento sul bus HA.
"""
from __future__ import annotations

from homeassistant.components.event import EventDeviceClass, EventEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, SIGNAL_EVENT

_EVENT_TYPES = ["motion", "person", "sound", "pet", "vehicle"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(EufyCameraEvent(coordinator, serial) for serial in coordinator.data)


class EufyCameraEvent(EventEntity):
    _attr_has_entity_name = True
    _attr_name = "Event"
    _attr_device_class = EventDeviceClass.MOTION
    _attr_event_types = _EVENT_TYPES

    def __init__(self, coordinator, serial: str) -> None:
        self.coordinator = coordinator
        self._serial = serial
        self._attr_unique_id = f"{serial}_event"

    @property
    def device_info(self) -> DeviceInfo:
        cam = self.coordinator.data.get(self._serial)
        return DeviceInfo(
            identifiers={(DOMAIN, self._serial)},
            name=cam.name if cam else self._serial,
            manufacturer="Eufy",
            model=cam.model if cam else None,
        )

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, SIGNAL_EVENT.format(serial=self._serial), self._handle_event
            )
        )

    @callback
    def _handle_event(self, event) -> None:
        if event.kind not in self._attr_event_types:
            return
        self._trigger_event(event.kind, {
            "event_type_code": event.event_type,
            "pic_url": event.pic_url,
            "name": event.name,
            "push_count": event.push_count,
        })
        self.async_write_ha_state()
