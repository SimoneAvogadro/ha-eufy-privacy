"""Config flow per eufy_privacy: login con 2FA e captcha."""
import logging

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, CONF_COUNTRY

from .const import DOMAIN
from .eufy_cloud import EufyCloudClient

_LOGGER = logging.getLogger(__name__)

USER_SCHEMA = vol.Schema({
    vol.Required(CONF_EMAIL): str,
    vol.Required(CONF_PASSWORD): str,
    vol.Required(CONF_COUNTRY, default="IT"): str,
})


class EufyPrivacyConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self):
        self._client: EufyCloudClient | None = None
        self._data: dict = {}
        self._captcha_id: str = ""

    async def async_step_user(self, user_input=None):
        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=USER_SCHEMA)
        self._data = user_input
        self._client = EufyCloudClient(
            country=user_input[CONF_COUNTRY],
            email=user_input[CONF_EMAIL],
            password=user_input[CONF_PASSWORD],
        )
        return await self._attempt(self._client.login)

    async def async_step_2fa(self, user_input=None):
        if user_input is None:
            return self.async_show_form(step_id="2fa",
                                        data_schema=vol.Schema({vol.Required("code"): str}))
        return await self._attempt(lambda: self._client.submit_2fa(user_input["code"]))

    async def async_step_captcha(self, user_input=None):
        if user_input is None:
            return self.async_show_form(
                step_id="captcha",
                data_schema=vol.Schema({vol.Required("answer"): str}),
                description_placeholders={"captcha_id": self._captcha_id},
            )
        return await self._attempt(
            lambda: self._client.submit_captcha(self._captcha_id, user_input["answer"]))

    async def _attempt(self, fn):
        try:
            result = await self.hass.async_add_executor_job(fn)
        except Exception as err:  # cloud irraggiungibile / risposta inattesa
            _LOGGER.exception("Errore di autenticazione Eufy: %s", err)
            return self.async_show_form(
                step_id="user", data_schema=USER_SCHEMA,
                errors={"base": "auth_failed"},
            )
        if result.status == "ok":
            await self.hass.async_add_executor_job(self._client.trust_device)
            state = await self.hass.async_add_executor_job(self._client.export_state)
            await self.async_set_unique_id(self._client.user_id or self._data[CONF_EMAIL])
            self._abort_if_unique_id_configured()
            return self.async_create_entry(
                title=self._data[CONF_EMAIL],
                data={**self._data, "state": state},
            )
        if result.status == "need_2fa":
            return await self.async_step_2fa()
        if result.status == "need_captcha":
            self._captcha_id = result.captcha_id
            return await self.async_step_captcha()
        return self.async_show_form(
            step_id="user", data_schema=USER_SCHEMA,
            errors={"base": "auth_failed"},
        )
