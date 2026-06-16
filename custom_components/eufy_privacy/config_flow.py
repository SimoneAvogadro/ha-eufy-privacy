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
        self._captcha_image: str = ""
        self._reauth_entry = None

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
                # passo entrambi i placeholder: così una traduzione vecchia
                # ancora in cache (che usa {captcha_id}) non va in MISSING_VALUE.
                description_placeholders={
                    "captcha_image": self._captcha_image,
                    "captcha_id": self._captcha_id,
                },
            )
        return await self._attempt(
            lambda: self._client.submit_captcha(self._captcha_id, user_input["answer"]))

    async def async_step_reauth(self, entry_data):
        """Avviato da HA quando il token scade e serve un nuovo login."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"])
        self._data = dict(entry_data)
        state = dict(entry_data.get("state", {}))
        self._client = EufyCloudClient.from_state(
            entry_data[CONF_EMAIL], entry_data[CONF_PASSWORD], state)
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        if user_input is None:
            return self.async_show_form(
                step_id="reauth_confirm",
                data_schema=vol.Schema({vol.Optional(CONF_PASSWORD): str}),
                description_placeholders={"email": self._data.get(CONF_EMAIL, "")},
            )
        if user_input.get(CONF_PASSWORD):
            self._data[CONF_PASSWORD] = user_input[CONF_PASSWORD]
            self._client.password = user_input[CONF_PASSWORD]
        return await self._attempt(self._client.login)

    async def _attempt(self, fn):
        try:
            result = await self.hass.async_add_executor_job(fn)
        except Exception as err:  # cloud irraggiungibile / risposta inattesa
            _LOGGER.exception("Errore di autenticazione Eufy: %s", err)
            return self._show_error()
        if result.status == "ok":
            await self.hass.async_add_executor_job(self._client.trust_device)
            state = await self.hass.async_add_executor_job(self._client.export_state)
            if self._reauth_entry is not None:
                return self.async_update_reload_and_abort(
                    self._reauth_entry,
                    data={**self._reauth_entry.data, **self._data, "state": state},
                    reason="reauth_successful",
                )
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
            self._captcha_image = result.captcha_image
            return await self.async_step_captcha()
        return self._show_error()

    def _show_error(self):
        """Ripresenta lo step iniziale (user o reauth) con errore di auth."""
        if self._reauth_entry is not None:
            return self.async_show_form(
                step_id="reauth_confirm",
                data_schema=vol.Schema({vol.Optional(CONF_PASSWORD): str}),
                description_placeholders={"email": self._data.get(CONF_EMAIL, "")},
                errors={"base": "auth_failed"},
            )
        return self.async_show_form(
            step_id="user", data_schema=USER_SCHEMA,
            errors={"base": "auth_failed"},
        )
