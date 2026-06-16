"""Switch privacy: uno per camera. assumed_state (nessun polling automatico)."""
from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .eufy_cloud import EufyCloudError


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        EufyPrivacySwitch(coordinator, serial) for serial in coordinator.data
    )


class EufyPrivacySwitch(CoordinatorEntity, SwitchEntity):
    _attr_assumed_state = True
    _attr_has_entity_name = True
    _attr_name = "Privacy"
    _attr_icon = "mdi:eye-off"

    def __init__(self, coordinator, serial: str):
        super().__init__(coordinator)
        self._serial = serial
        self._attr_unique_id = f"{serial}_privacy"
        self._optimistic = None

    @property
    def _camera(self):
        return self.coordinator.data.get(self._serial)

    @property
    def device_info(self) -> DeviceInfo:
        cam = self._camera
        return DeviceInfo(
            identifiers={(DOMAIN, self._serial)},
            name=cam.name if cam else self._serial,
            manufacturer="Eufy",
            model=cam.model if cam else None,
        )

    @property
    def is_on(self) -> bool | None:
        if self._optimistic is not None:
            return self._optimistic
        cam = self._camera
        return cam.privacy_on if cam else None

    async def async_turn_on(self, **kwargs) -> None:
        await self._set(True)

    async def async_turn_off(self, **kwargs) -> None:
        await self._set(False)

    async def _set(self, on: bool) -> None:
        cam = self._camera
        if cam is None:
            return
        try:
            await self.hass.async_add_executor_job(
                self.coordinator.client.set_privacy, cam, on
            )
        except EufyCloudError as err:
            raise HomeAssistantError(f"Impossibile impostare la privacy: {err}") from err
        self._optimistic = on
        self.async_write_ha_state()

    def _handle_coordinator_update(self) -> None:
        # dopo un refresh reale, abbandona lo stato ottimistico
        self._optimistic = None
        super()._handle_coordinator_update()
