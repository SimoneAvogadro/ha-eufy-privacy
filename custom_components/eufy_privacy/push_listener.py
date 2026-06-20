"""Ascolto eventi push Eufy (motion/person/sound/...) via MQTT, in un thread paho.

Architettura (vedi piano): paho gira nel SUO thread (`loop_start`); ogni callback gira FUORI
dal loop HA, quindi l'handoff alle entita' passa SEMPRE per `hass.add_job(...)` (thread-safe),
che esegue `async_dispatcher_send(SIGNAL_EVENT)` sul loop. MQTT e' la via primaria (semplice);
se il gate live mostra che i motion non arrivano qui, il fallback e' FCM (mtalk.google.com).
"""
from __future__ import annotations

import logging
import socket
import ssl

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .const import MQTT_HOST, MQTT_PORT, SIGNAL_EVENT
from .eufy_cloud import parse_push_message

_LOGGER = logging.getLogger(__name__)

# IP del NLB visto resettare il TLS negli esperimenti: lo escludiamo SOLO per questo client
# (NON con un monkeypatch globale di socket.getaddrinfo, che corromperebbe il DNS di tutta HA).
_BAD_IP = "63.176.85.119"


class EufyPushListener:
    """Gestisce il ciclo di vita del client MQTT push e dispatch degli eventi alle entita'."""

    def __init__(self, hass: HomeAssistant, coordinator) -> None:
        self.hass = hass
        self.coordinator = coordinator
        self._client = None
        self._started = False

    def _resolve_host(self) -> str:
        """Risolve un IP valido per il broker, escludendo l'IP rotto noto. Fallback: hostname."""
        try:
            infos = socket.getaddrinfo(MQTT_HOST, MQTT_PORT, proto=socket.IPPROTO_TCP)
            ips = [i[4][0] for i in infos if i[4][0] != _BAD_IP]
            return ips[0] if ips else MQTT_HOST
        except OSError:
            return MQTT_HOST

    # ── Avvio/stop (parte bloccante in executor) ─────────────────────────────
    async def async_start(self) -> None:
        client = self.coordinator.client
        if not client.user_id:
            _LOGGER.warning("Push MQTT non avviato: user_id assente (login non completato).")
            return
        await self.hass.async_add_executor_job(self._build_and_connect)
        self._started = True

    def _build_and_connect(self) -> None:
        import paho.mqtt.client as mqtt

        client = self.coordinator.client
        user_id = client.user_id
        cid = f"android_EufySecurity_{user_id}_{client.openudid or '0000000000000000'}"
        c = mqtt.Client(client_id=cid, protocol=mqtt.MQTTv311,
                        callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        c.username_pw_set(f"eufy_{user_id}", client.email)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        c.tls_set_context(ctx)
        c.reconnect_delay_set(min_delay=1, max_delay=120)
        c.on_connect = self._on_connect
        c.on_message = self._on_message
        c.on_disconnect = self._on_disconnect
        self._client = c
        c.connect_async(self._resolve_host(), MQTT_PORT, keepalive=60)
        c.loop_start()  # thread di rete proprio di paho

    async def async_stop(self) -> None:
        if not self._started or self._client is None:
            return
        await self.hass.async_add_executor_job(self._teardown)
        self._started = False

    def _teardown(self) -> None:
        try:
            self._client.loop_stop()
            self._client.disconnect()
        except Exception as err:  # noqa: BLE001 — teardown best-effort
            _LOGGER.debug("Errore in teardown MQTT (ignorato): %s", err)

    # ── Callback paho (girano sul THREAD di paho, non sul loop HA) ───────────
    def _on_connect(self, client, _userdata, _flags, reason_code, _props=None) -> None:
        user_id = self.coordinator.client.user_id
        _LOGGER.info("Push MQTT connesso (rc=%s); sottoscrivo gli eventi di %s", reason_code, user_id)
        client.subscribe(f"/phone/{user_id}/notice", 1)
        client.subscribe(f"/phone/{user_id}/#", 1)

    def _on_disconnect(self, _client, _userdata, *args) -> None:
        # paho riconnette da solo (reconnect_delay_set). Logghiamo soltanto.
        _LOGGER.debug("Push MQTT disconnesso (riconnessione automatica).")

    def _on_message(self, _client, _userdata, msg) -> None:
        event = parse_push_message(msg.payload)
        if event is None:
            return
        # marshalling thread paho -> loop HA: l'UNICO handoff sicuro.
        self.hass.add_job(self._dispatch_event, event)

    @callback
    def _dispatch_event(self, event) -> None:
        _LOGGER.debug("Evento push: %s %s (%s)", event.kind, event.serial, event.event_type)
        async_dispatcher_send(self.hass, SIGNAL_EVENT.format(serial=event.serial), event)
