"""Constants for the Eufy Privacy integration."""
from __future__ import annotations

from datetime import timedelta

DOMAIN = "eufy_privacy"
MANUFACTURER = "Eufy"

CONF_EMAIL = "email"
CONF_PASSWORD = "password"
CONF_COUNTRY = "country"
CONF_LANGUAGE = "language"
CONF_BRIDGE_URL = "bridge_url"
CONF_BRIDGE_TOKEN = "bridge_token"

DEFAULT_COUNTRY = "IT"
DEFAULT_LANGUAGE = "it"
DEFAULT_BRIDGE_URL = "http://local_eufy_bridge:8787"

UPDATE_INTERVAL = timedelta(minutes=10)
HTTP_TIMEOUT = 10.0
WS_BACKOFF_INITIAL = 1.0
WS_BACKOFF_MAX = 60.0

SERVICE_SET_PRIVACY_MODE = "set_privacy_mode"
ATTR_SERIAL = "serial"
ATTR_ENABLED = "enabled"

PLATFORMS = ["switch", "binary_sensor"]
