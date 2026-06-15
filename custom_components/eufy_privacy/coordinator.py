"""Coordinator for the Eufy bridge: push-driven with periodic reconciliation."""
from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .bridge import BridgeAuthError, BridgeClient, BridgeError, BridgeUnreachable
from .const import (
    CONF_COUNTRY,
    CONF_EMAIL,
    CONF_LANGUAGE,
    CONF_PASSWORD,
    DOMAIN,
    UPDATE_INTERVAL,
)

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class CameraState:
    serial: str
    name: str
    model: str | None
    online: bool | None
    privacy_enabled: bool | None
    station_serial: str | None
    battery_value: int | None

    @classmethod
    def from_payload(cls, p: dict[str, Any]) -> "CameraState":
        return cls(
            serial=p["serial"],
            name=p.get("name") or p["serial"],
            model=p.get("model"),
            online=p.get("online"),
            privacy_enabled=p.get("privacyEnabled"),
            station_serial=p.get("stationSerial"),
            battery_value=p.get("batteryValue"),
        )


@dataclass(frozen=True)
class BridgeStatus:
    cloud_connected: bool = False
    push_connected: bool = False


class EufyCoordinator(DataUpdateCoordinator[dict[str, CameraState]]):
    """Push-driven coordinator with a slow reconciliation poll (heartbeat).

    Real-time updates arrive via the WebSocket stream (see events.py) which
    calls apply_event_update(). The periodic refresh is only a safety net for
    events that were missed while the WS was disconnected.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        bridge: BridgeClient,
        credentials: dict[str, str],
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=UPDATE_INTERVAL,
        )
        self.bridge = bridge
        self._credentials = credentials
        self.bridge_status = BridgeStatus()

    async def _async_update_data(self) -> dict[str, CameraState]:
        try:
            cameras = await self.bridge.list_cameras()
        except BridgeError as err:
            # bridge restarted o token Eufy scaduto → ricarico la sessione
            if isinstance(err, (BridgeUnreachable, BridgeAuthError)) or "not initialised" in str(err):
                _LOGGER.info("Re-initialising bridge session: %s", err)
                try:
                    await self.bridge.init(
                        email=self._credentials[CONF_EMAIL],
                        password=self._credentials[CONF_PASSWORD],
                        country=self._credentials[CONF_COUNTRY],
                        language=self._credentials[CONF_LANGUAGE],
                    )
                    cameras = await self.bridge.list_cameras()
                except BridgeError as retry_err:
                    raise UpdateFailed(str(retry_err)) from retry_err
            else:
                raise UpdateFailed(str(err)) from err

        return {c["serial"]: CameraState.from_payload(c) for c in cameras}

    async def async_set_privacy(self, serial: str, enabled: bool) -> None:
        """Toggle privacy; non chiede refresh, l'evento push arriverà via WS."""
        await self.bridge.set_privacy(serial, enabled)

    def apply_event_update(self, serial: str, **fields: Any) -> None:
        """Mutate the cached CameraState for `serial` and notify listeners.

        Called from the WS event stream. fields are CameraState attributes
        (privacy_enabled, online, battery_value, ...).
        """
        data = dict(self.data or {})
        current = data.get(serial)
        if current is None:
            # Serial sconosciuto: probabilmente devices_changed in arrivo.
            _LOGGER.debug("Event for unknown serial %s, ignoring", serial)
            return
        data[serial] = replace(current, **fields)
        self.async_set_updated_data(data)

    def update_bridge_status(self, *, cloud_connected: bool | None = None,
                             push_connected: bool | None = None) -> None:
        new = BridgeStatus(
            cloud_connected=self.bridge_status.cloud_connected if cloud_connected is None else cloud_connected,
            push_connected=self.bridge_status.push_connected if push_connected is None else push_connected,
        )
        if new != self.bridge_status:
            self.bridge_status = new
            # Triggera la propagazione anche se la cache cameras non cambia.
            self.async_update_listeners()
