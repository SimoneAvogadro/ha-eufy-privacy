"""Privacy switch per camera."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .bridge import BridgeError
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
        EufyPrivacySwitch(coordinator, serial)
        for serial in (coordinator.data or {}).keys()
    )


class EufyPrivacySwitch(CoordinatorEntity[EufyCoordinator], SwitchEntity):
    _attr_has_entity_name = True
    _attr_name = "Privacy"
    _attr_icon = "mdi:eye-off"

    def __init__(self, coordinator: EufyCoordinator, serial: str) -> None:
        super().__init__(coordinator)
        self._serial = serial
        self._attr_unique_id = f"{serial}_privacy"

    def _cam(self) -> CameraState | None:
        return (self.coordinator.data or {}).get(self._serial)

    @property
    def available(self) -> bool:
        cam = self._cam()
        return cam is not None and cam.privacy_enabled is not None

    @property
    def is_on(self) -> bool | None:
        cam = self._cam()
        return cam.privacy_enabled if cam else None

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

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._toggle(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._toggle(False)

    async def _toggle(self, enabled: bool) -> None:
        try:
            await self.coordinator.async_set_privacy(self._serial, enabled)
        except BridgeError as err:
            raise HomeAssistantError(f"Privacy toggle failed: {err}") from err
