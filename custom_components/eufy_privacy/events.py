"""Persistent WebSocket consumer for bridge push events."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import aiohttp

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .bridge import BridgeClient
from .const import WS_BACKOFF_INITIAL, WS_BACKOFF_MAX
from .coordinator import EufyCoordinator

_LOGGER = logging.getLogger(__name__)


class EufyEventStream:
    """Connects to ws://bridge/events, applies updates to the coordinator,
    reconnects with exponential backoff on failure.
    """

    def __init__(self, bridge: BridgeClient, coordinator: EufyCoordinator) -> None:
        self._bridge = bridge
        self._coordinator = coordinator
        self._task: asyncio.Task | None = None
        self._stopping = False

    def start(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Start the consumer loop as a background task tracked by HA."""
        self._stopping = False
        self._task = entry.async_create_background_task(
            hass, self._run(), name="eufy_privacy_ws_stream"
        )

    async def stop(self) -> None:
        self._stopping = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    async def _run(self) -> None:
        backoff = WS_BACKOFF_INITIAL
        while not self._stopping:
            try:
                ws = await self._bridge.ws_connect()
            except Exception as err:  # noqa: BLE001
                _LOGGER.warning("WS connect failed (%s), retrying in %.1fs", err, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, WS_BACKOFF_MAX)
                continue

            _LOGGER.info("Connected to bridge events")
            backoff = WS_BACKOFF_INITIAL
            try:
                # Heartbeat dopo riconnessione: la cache potrebbe essere stantia
                # se sono stati persi eventi mentre eravamo disconnessi.
                await self._coordinator.async_request_refresh()
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        await self._handle_message(msg.data)
                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        _LOGGER.warning("WS error: %s", ws.exception())
                        break
                    elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED):
                        break
            except Exception as err:  # noqa: BLE001
                _LOGGER.warning("WS loop crashed: %s", err)
            finally:
                if not ws.closed:
                    await ws.close()

            if self._stopping:
                break
            _LOGGER.info("WS disconnected, reconnecting in %.1fs", backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, WS_BACKOFF_MAX)

    async def _handle_message(self, raw: str) -> None:
        try:
            event: dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError:
            _LOGGER.warning("Bad JSON from bridge: %s", raw[:200])
            return

        etype = event.get("type")
        if etype == "privacy_changed":
            self._coordinator.apply_event_update(
                event["serial"],
                privacy_enabled=event.get("privacyEnabled"),
            )
        elif etype == "battery_changed":
            self._coordinator.apply_event_update(
                event["serial"],
                battery_value=event.get("batteryValue"),
            )
        elif etype == "devices_changed":
            # La lista delle camere è cambiata: ri-fetcho lo snapshot.
            await self._coordinator.async_request_refresh()
        elif etype == "bridge_status":
            self._coordinator.update_bridge_status(
                cloud_connected=event.get("cloudConnected"),
                push_connected=event.get("pushConnected"),
            )
        else:
            _LOGGER.debug("Unhandled event type: %s", etype)
