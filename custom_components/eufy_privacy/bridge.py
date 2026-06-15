"""HTTP client wrapper around the Node.js eufy-bridge add-on."""
from __future__ import annotations

import logging
from typing import Any

import aiohttp

from .const import HTTP_TIMEOUT

_LOGGER = logging.getLogger(__name__)


class BridgeError(Exception):
    """Generic bridge failure."""


class BridgeAuthError(BridgeError):
    """Eufy auth failed (CAPTCHA / 2FA / wrong password)."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


class BridgeUnreachable(BridgeError):
    """Bridge add-on not reachable on the network."""


class BridgeClient:
    """Thin async wrapper around the bridge REST API."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        token: str | None,
    ) -> None:
        self._session = session
        self._base = base_url.rstrip("/")
        self._token = token

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._token:
            h["X-Bridge-Token"] = self._token
        return h

    async def healthz(self) -> dict[str, Any]:
        return await self._request("GET", "/healthz", auth=False)

    async def init(
        self,
        email: str,
        password: str,
        country: str,
        language: str,
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            "/init",
            json={
                "email": email,
                "password": password,
                "country": country,
                "language": language,
            },
        )

    async def list_cameras(self) -> list[dict[str, Any]]:
        data = await self._request("GET", "/cameras")
        if not isinstance(data, list):
            raise BridgeError(f"Unexpected /cameras payload: {data!r}")
        return data

    async def set_privacy(self, serial: str, enabled: bool) -> None:
        await self._request(
            "POST",
            f"/cameras/{serial}/privacy",
            json={"enabled": enabled},
        )

    async def ws_connect(self) -> aiohttp.ClientWebSocketResponse:
        """Open a persistent WS to /events. Caller owns the lifecycle."""
        ws_base = self._base.replace("http://", "ws://", 1).replace("https://", "wss://", 1)
        url = f"{ws_base}/events"
        headers = {}
        if self._token:
            headers["X-Bridge-Token"] = self._token
        return await self._session.ws_connect(
            url,
            headers=headers,
            heartbeat=30.0,
            autoclose=True,
            autoping=True,
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        auth: bool = True,
    ) -> Any:
        url = f"{self._base}{path}"
        headers = self._headers() if auth else {"Content-Type": "application/json"}
        try:
            async with self._session.request(
                method,
                url,
                json=json,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
            ) as resp:
                body: Any = None
                try:
                    body = await resp.json(content_type=None)
                except Exception:  # noqa: BLE001
                    body = await resp.text()
                if resp.status == 401:
                    raise BridgeAuthError("Bridge token rejected", code="BRIDGE_AUTH")
                if resp.status == 409 and isinstance(body, dict):
                    raise BridgeAuthError(
                        body.get("error", "auth failed"),
                        code=body.get("code"),
                    )
                if resp.status >= 400:
                    msg = body.get("error") if isinstance(body, dict) else str(body)
                    raise BridgeError(f"{resp.status} {msg}")
                return body
        except aiohttp.ClientConnectorError as err:
            raise BridgeUnreachable(str(err)) from err
        except TimeoutError as err:
            raise BridgeUnreachable("timeout talking to bridge") from err
