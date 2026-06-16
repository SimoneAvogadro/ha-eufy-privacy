"""Button 'Aggiorna stato' (update_now): legge lo stato privacy dal cloud on-demand."""
from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        EufyPrivacyUpdateNowButton(coordinator, serial) for serial in coordinator.data
    )


class EufyPrivacyUpdateNowButton(ButtonEntity):
    _attr_has_entity_name = True
    _attr_name = "Aggiorna stato"
    _attr_icon = "mdi:refresh"

    def __init__(self, coordinator, serial: str):
        self._coordinator = coordinator
        self._serial = serial
        self._attr_unique_id = f"{serial}_update_now"

    @property
    def device_info(self) -> DeviceInfo:
        cam = self._coordinator.data.get(self._serial)
        return DeviceInfo(
            identifiers={(DOMAIN, self._serial)},
            name=cam.name if cam else self._serial,
            manufacturer="Eufy",
            model=cam.model if cam else None,
        )

    async def async_press(self) -> None:
        await self._coordinator.async_request_refresh()
