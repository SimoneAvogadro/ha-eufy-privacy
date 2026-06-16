"""Coordinator senza polling automatico: refresh SOLO su richiesta (button update_now)."""
import logging

from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .eufy_cloud import EufyCloudError

_LOGGER = logging.getLogger(__name__)


class EufyPrivacyCoordinator(DataUpdateCoordinator):
    def __init__(self, hass, client):
        super().__init__(hass, _LOGGER, name="eufy_privacy", update_interval=None)
        self.client = client

    async def _async_update_data(self) -> dict:
        """Ritorna {serial: EufyCamera}. Chiamato solo da async_request_refresh()."""
        def _fetch():
            self.client.ensure_token()
            return {c.serial: c for c in self.client.list_cameras()}
        try:
            return await self.hass.async_add_executor_job(_fetch)
        except EufyCloudError as err:
            raise UpdateFailed(str(err)) from err
