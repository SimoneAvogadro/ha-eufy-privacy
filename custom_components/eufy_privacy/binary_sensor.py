"""Binary sensor motion/person per camera, pilotati dagli eventi push (dispatcher).

Non sono CoordinatorEntity: si accendono su SIGNAL_EVENT e si spengono da soli dopo
AUTO_OFF_SECONDS (stesso pattern async_call_later gia' usato in switch.py).
"""
from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_call_later

from .const import AUTO_OFF_SECONDS, DOMAIN, EVENT_KIND_TO_SENSORS, SIGNAL_EVENT

# (kind sensore, nome, device_class)
_SENSORS = (
    ("motion", "Motion", BinarySensorDeviceClass.MOTION),
    ("person", "Person", BinarySensorDeviceClass.OCCUPANCY),
)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    entities = []
    for serial in coordinator.data:
        for kind, name, dev_class in _SENSORS:
            entities.append(EufyEventBinarySensor(coordinator, serial, kind, name, dev_class))
    async_add_entities(entities)


class EufyEventBinarySensor(BinarySensorEntity):
    _attr_has_entity_name = True
    _attr_is_on = False

    def __init__(self, coordinator, serial: str, kind: str, name: str, dev_class) -> None:
        self.coordinator = coordinator
        self._serial = serial
        self._kind = kind
        self._attr_name = name
        self._attr_device_class = dev_class
        self._attr_unique_id = f"{serial}_{kind}"
        self._cancel_off = None

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
        # person accende sia person sia motion; motion solo motion; sound non accende nulla.
        if self._kind not in EVENT_KIND_TO_SENSORS.get(event.kind, ()):
            return
        self._attr_is_on = True
        self.async_write_ha_state()
        if self._cancel_off is not None:
            self._cancel_off()
        self._cancel_off = async_call_later(self.hass, AUTO_OFF_SECONDS, self._turn_off)

    @callback
    def _turn_off(self, _now) -> None:
        self._cancel_off = None
        self._attr_is_on = False
        self.async_write_ha_state()

    async def async_will_remove_from_hass(self) -> None:
        if self._cancel_off is not None:
            self._cancel_off()
            self._cancel_off = None
