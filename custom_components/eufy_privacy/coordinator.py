"""Coordinator senza polling automatico: refresh SOLO su richiesta (button update_now)."""
import logging

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .eufy_cloud import EufyCloudError

_LOGGER = logging.getLogger(__name__)


class EufyPrivacyCoordinator(DataUpdateCoordinator):
    def __init__(self, hass, client):
        super().__init__(hass, _LOGGER, name="eufy_privacy", update_interval=None)
        self.client = client

    def _fetch(self):
        """Eseguito in executor: rinnova il token e legge le camere.

        Ritorna (login_result | None, {serial: EufyCamera}). Se il token è
        scaduto e il re-login richiede 2FA/captcha, NON chiama list_cameras
        (eviterebbe un errore spurio) e lascia decidere a _async_update_data.
        """
        res = self.client.ensure_token()
        if res is not None and res.status != "ok":
            return res, {}
        return res, {c.serial: c for c in self.client.list_cameras()}

    async def _async_update_data(self) -> dict:
        """Ritorna {serial: EufyCamera}. Chiamato solo da async_request_refresh()."""
        try:
            res, cameras = await self.hass.async_add_executor_job(self._fetch)
        except EufyCloudError as err:
            raise UpdateFailed(str(err)) from err
        if res is not None and res.status != "ok":
            # token scaduto e re-login non automatico → avvia il reauth flow in UI
            raise ConfigEntryAuthFailed(f"Re-login richiede: {res.status}")
        return cameras
