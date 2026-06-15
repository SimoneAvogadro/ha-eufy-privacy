"""Online/offline binary_sensor per camera."""
from __future__ import annotations

import logging

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, MANUFACTURER
from .coordinator import CameraState, EufyCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: EufyCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    async_add_entities(
        EufyOnlineSensor(coordinator, serial)
        for serial in (coordinator.data or {}).keys()
    )


class EufyOnlineSensor(CoordinatorEntity[EufyCoordinator], BinarySensorEntity):
    _attr_has_entity_name = True
    _attr_name = "Online"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, coordinator: EufyCoordinator, serial: str) -> None:
        super().__init__(coordinator)
        self._serial = serial
        self._attr_unique_id = f"{serial}_online"

    def _cam(self) -> CameraState | None:
        return (self.coordinator.data or {}).get(self._serial)

    @property
    def available(self) -> bool:
        cam = self._cam()
        return cam is not None and cam.online is not None

    @property
    def is_on(self) -> bool | None:
        cam = self._cam()
        return cam.online if cam else None

    @property
    def device_info(self) -> DeviceInfo:
        cam = self._cam()
        return DeviceInfo(
            identifiers={(DOMAIN, self._serial)},
            name=cam.name if cam else self._serial,
            manufacturer=MANUFACTURER,
            model=cam.model if cam else None,
            serial_number=self._serial,
        )
