# Eufy Privacy — Home Assistant Integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a pure-Python Home Assistant custom integration that lists Eufy cameras and toggles their privacy mode via the Eufy cloud HTTP API — no Node.js, no P2P.

**Architecture:** A standalone, HA-agnostic sync client library (`eufy_cloud.py`, `requests` + `cryptography`) that does login/ECDH+AES/list/set-privacy, wrapped by a thin HA layer (config_flow, manual-refresh coordinator, one `switch` + one `update_now` `button` per camera). Blocking client calls run via `hass.async_add_executor_job`.

**Tech Stack:** Python 3.10, `requests`, `cryptography` (both already in HA core), `pytest` + `unittest.mock` for tests. HA 2026.6.x.

**Key validated facts (from the spike, see `spike_eufy_cloud.py`):**
- Reuse/login token in header `X-Auth-Token`; `gtoken = md5(user_id)`.
- Responses (`device_list`, etc.) are AES-256-CBC encrypted, key = ECDH(prime256v1) shared secret, IV = key[:16], body base64.
- Write privacy via `POST v1/app/upload_devs_params` with `params:[{param_type, param_value}]`, **`param_value` MUST be a string** (`"1"`/`"0"`); int → HTTP 400 empty body.
- Privacy param types: `1035` (CMD_DEVS_SWITCH / DeviceEnabled) and `6250`. On Box (T8419): `"0"` = privacy OFF (camera active), `"1"` = privacy ON. Both params mirror; write both when present.
- API base resolved via `GET https://extend.eufylife.com/domain/<COUNTRY>` → `https://security-app-eu.eufylife.com`.

**Implementation note (deviation from spec):** the lib is **synchronous `requests`** (matches the proven spike, no new runtime deps — `requests` ships with HA), wrapped in executor jobs by the HA layer. Functionally identical to the aiohttp plan in the spec.

---

## File Structure

```
HA/
  custom_components/eufy_privacy/
    __init__.py            # setup/unload entry; build client; one initial refresh
    manifest.json          # domain, version, requirements (satisfied by core), config_flow:true
    const.py               # DOMAIN, endpoints, headers, param types, server bootstrap key
    eufy_cloud.py          # THE LIB: pure crypto/parse fns + EufyCloudClient (no HA imports)
    coordinator.py         # EufyPrivacyCoordinator: manual-only refresh (update_interval=None)
    config_flow.py         # steps: user / 2fa / captcha / reauth
    switch.py              # EufyPrivacySwitch (assumed_state, 1 per camera)
    button.py              # EufyPrivacyUpdateNowButton (1 per camera)
    strings.json
    translations/it.json
  tests/
    test_eufy_cloud.py     # offline + mocked-HTTP unit tests for the lib
  cli.py                   # standalone CLI: list / privacy <serial> <on|off>
  requirements-test.txt
```

Tests and the lib are developed and run **locally** in `/mnt/c/Simone/Eufy/HA/`.
The HA layer is validated by **deploying** to the RPi (`/config/custom_components/`).

---

## Task 0: Scaffolding & test env

**Files:**
- Create: `HA/custom_components/eufy_privacy/__init__.py` (empty package marker for now)
- Create: `HA/custom_components/eufy_privacy/const.py`
- Create: `HA/tests/__init__.py` (empty)
- Create: `HA/requirements-test.txt`
- Create: `HA/pytest.ini`

- [ ] **Step 1: Create the package dirs and empty markers**

```bash
cd /mnt/c/Simone/Eufy/HA
mkdir -p custom_components/eufy_privacy/translations tests
: > custom_components/eufy_privacy/__init__.py
: > tests/__init__.py
```

- [ ] **Step 2: Write `const.py`**

Create `HA/custom_components/eufy_privacy/const.py`:

```python
"""Costanti per l'integrazione eufy_privacy."""

DOMAIN = "eufy_privacy"

# Endpoint cloud Eufy
DOMAIN_BASE = "https://extend.eufylife.com"
EP_DOMAIN = "domain/{country}"
EP_LOGIN = "v2/passport/login_sec"
EP_SEND_VERIFY = "v1/sms/send/verify_code"
EP_TRUST_LIST = "v1/app/trust_device/list"
EP_TRUST_ADD = "v1/app/trust_device/add"
EP_DEVICE_LIST = "v2/house/device_list"
EP_SET_PARAMS = "v1/app/upload_devs_params"

# Chiave pubblica server "bootstrap" usata SOLO per cifrare la password al login
# (poi il server restituisce la propria server_secret_info.public_key).
SERVER_PUBLIC_KEY_BOOTSTRAP = (
    "04c5c00c4f8d1197cc7c3167c52bf7acb054d722f0ef08dcd7e0883236e0d72a"
    "3868d9750cb47fa4619248f3d83f0f662671dadc6e2d31c2f41db0161651c7c076"
)

# Param type cloud per lo stato privacy / DeviceEnabled
PARAM_DEVS_SWITCH = 1035
PARAM_PRIVACY_6250 = 6250
PRIVACY_PARAM_TYPES = (PARAM_DEVS_SWITCH, PARAM_PRIVACY_6250)

# Header di default replicati da eufy-security-client
BASE_HEADERS = {
    "App_version": "v4.6.0_1630",
    "Os_type": "android",
    "Os_version": "31",
    "Phone_model": "ONEPLUS A3003",
    "Net_type": "wifi",
    "Mnc": "02",
    "Mcc": "262",
    "Sn": "75814221ee75",
    "Model_type": "PHONE",
    "Cache-Control": "no-cache",
    "Timezone": "GMT+01:00",
}

# Codici risposta login (dal sorgente di bropat)
CODE_OK = 0
CODE_NEED_VERIFY_CODE = 26052
CODE_NEED_CAPTCHA = 26050
CODE_CAPTCHA_ERROR = 26051
```

> Note: `CODE_*` values come from bropat's `ResponseErrorCode`. `CODE_OK`/`CODE_WHATEVER_ERROR`
> is `0` (success). Verify `26050/26051/26052` against `node_modules/eufy-security-client/build/http/types.js`
> during implementation; adjust if different.

- [ ] **Step 3: Verify the bootstrap/captcha codes against the JS source**

Run:
```bash
cd /mnt/c/Simone/Eufy/node_modules/eufy-security-client/build/http
grep -nE 'CODE_NEED_VERIFY_CODE|LOGIN_NEED_CAPTCHA|LOGIN_CAPTCHA_ERROR|CODE_WHATEVER_ERROR' types.js
```
Expected: numeric assignments. Update `const.py` `CODE_*` to match exactly.

- [ ] **Step 4: Write `requirements-test.txt` and `pytest.ini`**

`HA/requirements-test.txt`:
```
pytest>=7
requests
cryptography
```

`HA/pytest.ini`:
```ini
[pytest]
testpaths = tests
python_files = test_*.py
```

- [ ] **Step 5: Install test deps**

Run:
```bash
cd /mnt/c/Simone/Eufy/HA && python3 -m pip install --user -r requirements-test.txt
python3 -m pytest --version
```
Expected: pytest version prints. If `pip install --user` is blocked, retry with a venv:
`python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements-test.txt`.

- [ ] **Step 6: Commit** (skip if not a git repo; otherwise:)

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "chore(eufy_privacy): scaffolding + const + test env"
```

---

## Task 1: ECDH shared secret

**Files:**
- Modify: `HA/custom_components/eufy_privacy/eufy_cloud.py` (create)
- Test: `HA/tests/test_eufy_cloud.py` (create)

- [ ] **Step 1: Write the failing test**

Create `HA/tests/test_eufy_cloud.py`:
```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "custom_components", "eufy_privacy"))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import eufy_cloud as ec_lib


def _keypair():
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_hex = priv.public_key().public_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.X962,
        format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.UncompressedPoint,
    ).hex()
    priv_hex = format(priv.private_numbers().private_value, "x")
    return priv_hex, pub_hex


def test_ecdh_shared_secret_is_symmetric():
    a_priv, a_pub = _keypair()
    b_priv, b_pub = _keypair()
    s1 = ec_lib.ecdh_shared_secret(a_priv, b_pub)
    s2 = ec_lib.ecdh_shared_secret(b_priv, a_pub)
    assert s1 == s2
    assert len(s1) == 32
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /mnt/c/Simone/Eufy/HA && python3 -m pytest tests/test_eufy_cloud.py::test_ecdh_shared_secret_is_symmetric -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'eufy_cloud'`.

- [ ] **Step 3: Write minimal implementation**

Create `HA/custom_components/eufy_privacy/eufy_cloud.py`:
```python
"""Client cloud Eufy pure-Python (sincrono). Nessun import di Home Assistant.

Implementa i soli metodi che servono: login (+2FA/captcha), trust device,
lista camere, set privacy. Crittografia ECDH(prime256v1)+AES-256-CBC.
"""
from __future__ import annotations

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec


def ecdh_shared_secret(client_private_key_hex: str, server_public_key_hex: str) -> bytes:
    """Segreto condiviso ECDH (coordinata X, 32 byte) come Node `computeSecret`."""
    priv = ec.derive_private_key(
        int(client_private_key_hex, 16), ec.SECP256R1(), default_backend()
    )
    server_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), bytes.fromhex(server_public_key_hex)
    )
    return priv.exchange(ec.ECDH(), server_pub)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /mnt/c/Simone/Eufy/HA && python3 -m pytest tests/test_eufy_cloud.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "feat(eufy_cloud): ECDH shared secret"
```

---

## Task 2: AES encrypt/decrypt round-trip

**Files:**
- Modify: `HA/custom_components/eufy_privacy/eufy_cloud.py`
- Test: `HA/tests/test_eufy_cloud.py`

- [ ] **Step 1: Write the failing test** (append)

```python
def test_encrypt_decrypt_roundtrip():
    a_priv, a_pub = _keypair()
    b_priv, b_pub = _keypair()
    key = ec_lib.ecdh_shared_secret(a_priv, b_pub)
    payload = '{"hello":"mondo","n":42}'
    enc = ec_lib.encrypt_api_data(payload, key)
    assert isinstance(enc, str)
    dec = ec_lib.decrypt_api_data(enc, ec_lib.ecdh_shared_secret(b_priv, a_pub))
    assert dec == payload
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest tests/test_eufy_cloud.py::test_encrypt_decrypt_roundtrip -v`
Expected: FAIL — `AttributeError: module 'eufy_cloud' has no attribute 'encrypt_api_data'`.

- [ ] **Step 3: Implement** (append to `eufy_cloud.py`)

```python
import base64
from cryptography.hazmat.primitives import padding as _padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_api_data(plaintext: str, key: bytes) -> str:
    """AES-256-CBC + PKCS7, IV=key[:16], output base64 (come Node encryptAPIData)."""
    padder = _padding.PKCS7(128).padder()
    data = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(key[:16]), default_backend()).encryptor()
    return base64.b64encode(enc.update(data) + enc.finalize()).decode("ascii")


def decrypt_api_data(b64data: str, key: bytes) -> str:
    """Inverso di encrypt_api_data. Tollera padding/terminatore null residuo."""
    raw = base64.b64decode(b64data)
    dec = Cipher(algorithms.AES(key), modes.CBC(key[:16]), default_backend()).decryptor()
    out = dec.update(raw) + dec.finalize()
    try:
        unpadder = _padding.PKCS7(128).unpadder()
        out = unpadder.update(out) + unpadder.finalize()
    except ValueError:
        if out and 1 <= out[-1] <= 16:
            out = out[: -out[-1]]
    nul = out.find(b"\x00")
    if nul != -1:
        out = out[:nul]
    return out.decode("utf-8", errors="replace")
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m pytest tests/test_eufy_cloud.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "feat(eufy_cloud): AES encrypt/decrypt round-trip"
```

---

## Task 3: Privacy state mapping & param payload

**Files:**
- Modify: `HA/custom_components/eufy_privacy/eufy_cloud.py`
- Test: `HA/tests/test_eufy_cloud.py`

- [ ] **Step 1: Write the failing test** (append)

```python
def test_is_privacy_on_reads_1035_then_6250():
    assert ec_lib.is_privacy_on({1035: "1"}) is True
    assert ec_lib.is_privacy_on({1035: "0"}) is False
    assert ec_lib.is_privacy_on({6250: "1"}) is True      # fallback
    assert ec_lib.is_privacy_on({}) is False               # default


def test_build_privacy_params_uses_strings_for_present_types():
    params = ec_lib.build_privacy_params(True, available_types={1035, 6250})
    assert {"param_type": 1035, "param_value": "1"} in params
    assert {"param_type": 6250, "param_value": "1"} in params
    # solo i type presenti
    only = ec_lib.build_privacy_params(False, available_types={1035})
    assert only == [{"param_type": 1035, "param_value": "0"}]
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest tests/test_eufy_cloud.py -k "privacy" -v`
Expected: FAIL — attributes missing.

- [ ] **Step 3: Implement** (append; add imports at top of file)

```python
from .const import PARAM_DEVS_SWITCH, PARAM_PRIVACY_6250, PRIVACY_PARAM_TYPES
```
> When run as a standalone module (CLI/tests, no package), use a fallback import.
> Put this at the top of `eufy_cloud.py` instead of the line above:
```python
try:
    from .const import PARAM_DEVS_SWITCH, PARAM_PRIVACY_6250, PRIVACY_PARAM_TYPES
except ImportError:  # esecuzione come modulo standalone (test/CLI)
    from const import PARAM_DEVS_SWITCH, PARAM_PRIVACY_6250, PRIVACY_PARAM_TYPES
```

Then the functions:
```python
def is_privacy_on(params: dict) -> bool:
    """True se la privacy è attiva. Legge 1035, poi 6250. Default False."""
    for pt in (PARAM_DEVS_SWITCH, PARAM_PRIVACY_6250):
        if pt in params and params[pt] is not None:
            return str(params[pt]) == "1"
    return False


def build_privacy_params(on: bool, available_types: set[int]) -> list[dict]:
    """Payload per upload_devs_params: param_value SEMPRE stringa, solo i type presenti."""
    value = "1" if on else "0"
    return [
        {"param_type": pt, "param_value": value}
        for pt in PRIVACY_PARAM_TYPES
        if pt in available_types
    ]
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m pytest tests/test_eufy_cloud.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "feat(eufy_cloud): privacy state mapping + param payload (string values)"
```

---

## Task 4: Parse cameras from a decrypted device_list

**Files:**
- Modify: `HA/custom_components/eufy_privacy/eufy_cloud.py`
- Test: `HA/tests/test_eufy_cloud.py`

- [ ] **Step 1: Write the failing test** (append)

```python
def test_parse_cameras_extracts_fields_and_privacy():
    decrypted = [
        {
            "device_name": "Box",
            "device_sn": "T8000P0000000000",
            "station_sn": "T8000P0000000000",
            "device_model": "T8419",
            "params": [
                {"param_type": 1035, "param_value": "1"},
                {"param_type": 6250, "param_value": "1"},
                {"param_type": 1107, "param_value": "x"},
            ],
        }
    ]
    cams = ec_lib.parse_cameras(decrypted)
    assert len(cams) == 1
    c = cams[0]
    assert c.name == "Box"
    assert c.serial == "T8000P0000000000"
    assert c.station_sn == "T8000P0000000000"
    assert c.model == "T8419"
    assert c.privacy_on is True
    assert c.available_param_types == {1035, 6250}
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest tests/test_eufy_cloud.py -k parse -v`
Expected: FAIL — no `parse_cameras` / `EufyCamera`.

- [ ] **Step 3: Implement** (append; add `from dataclasses import dataclass, field` at top)

```python
from dataclasses import dataclass, field


@dataclass
class EufyCamera:
    name: str
    serial: str
    station_sn: str
    model: str
    privacy_on: bool
    available_param_types: set = field(default_factory=set)


def _params_dict(device: dict) -> dict:
    out = {}
    for p in device.get("params", []):
        try:
            out[int(p["param_type"])] = p.get("param_value")
        except (KeyError, ValueError, TypeError):
            continue
    return out


def parse_cameras(decrypted_device_list: list) -> list:
    cams = []
    for d in decrypted_device_list:
        params = _params_dict(d)
        cams.append(
            EufyCamera(
                name=d.get("device_name", ""),
                serial=d.get("device_sn", ""),
                station_sn=d.get("station_sn", d.get("device_sn", "")),
                model=d.get("device_model", ""),
                privacy_on=is_privacy_on(params),
                available_param_types={pt for pt in params if pt in PRIVACY_PARAM_TYPES},
            )
        )
    return cams
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m pytest tests/test_eufy_cloud.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "feat(eufy_cloud): parse cameras from device_list"
```

---

## Task 5: Client skeleton — headers, state export/import

**Files:**
- Modify: `HA/custom_components/eufy_privacy/eufy_cloud.py`
- Test: `HA/tests/test_eufy_cloud.py`

- [ ] **Step 1: Write the failing test** (append)

```python
def test_client_headers_and_state_roundtrip():
    client = ec_lib.EufyCloudClient(
        country="IT", email="a@b.c", password="pw",
        openudid="abc123",
    )
    client.token = "TOK"
    client.user_id = "uid123"
    h = client._headers()
    assert h["X-Auth-Token"] == "TOK"
    assert h["Country"] == "IT"
    assert h["Openudid"] == "abc123"
    assert h["gtoken"] == ec_lib.md5_hex("uid123")

    state = client.export_state()
    client2 = ec_lib.EufyCloudClient.from_state("a@b.c", "pw", state)
    assert client2.token == "TOK"
    assert client2.user_id == "uid123"
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest tests/test_eufy_cloud.py -k "headers_and_state" -v`
Expected: FAIL.

- [ ] **Step 3: Implement** (append; add `import hashlib, time` at top)

```python
import hashlib
import time
import requests

from .const import (  # usa lo stesso try/except fallback del task 3 se necessario
    BASE_HEADERS, DOMAIN_BASE, EP_DOMAIN, SERVER_PUBLIC_KEY_BOOTSTRAP,
)


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


class EufyCloudError(Exception):
    pass


class EufyCloudClient:
    def __init__(self, country, email, password, *, openudid="",
                 client_private_key=None, server_public_key=None,
                 token=None, token_expiration=None, user_id=None, api_base=None):
        self.country = country.upper()
        self.email = email
        self.password = password
        self.openudid = openudid
        # genera una coppia ECDH se non fornita
        if client_private_key:
            self.client_private_key = client_private_key
        else:
            priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
            self.client_private_key = format(priv.private_numbers().private_value, "x")
        self.server_public_key = server_public_key or SERVER_PUBLIC_KEY_BOOTSTRAP
        self.token = token
        self.token_expiration = token_expiration  # epoch seconds
        self.user_id = user_id
        self.api_base = api_base
        self._session = requests.Session()
        # stato login intermedio (2FA/captcha)
        self._pending_login = None

    # --- header / stato ---
    def _client_public_key_hex(self) -> str:
        priv = ec.derive_private_key(
            int(self.client_private_key, 16), ec.SECP256R1(), default_backend()
        )
        return priv.public_key().public_bytes(
            encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.X962,
            format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.UncompressedPoint,
        ).hex()

    def _headers(self) -> dict:
        h = dict(BASE_HEADERS)
        h["Country"] = self.country
        h["Language"] = "it"
        h["Openudid"] = self.openudid
        if self.token:
            h["X-Auth-Token"] = self.token
        if self.user_id:
            h["gtoken"] = md5_hex(self.user_id)
        return h

    def export_state(self) -> dict:
        return {
            "client_private_key": self.client_private_key,
            "server_public_key": self.server_public_key,
            "token": self.token,
            "token_expiration": self.token_expiration,
            "user_id": self.user_id,
            "openudid": self.openudid,
            "api_base": self.api_base,
        }

    @classmethod
    def from_state(cls, email, password, state: dict) -> "EufyCloudClient":
        return cls(
            country=state.get("country", "IT"),
            email=email, password=password,
            openudid=state.get("openudid", ""),
            client_private_key=state.get("client_private_key"),
            server_public_key=state.get("server_public_key"),
            token=state.get("token"),
            token_expiration=state.get("token_expiration"),
            user_id=state.get("user_id"),
            api_base=state.get("api_base"),
        )
```
> If `from_state` needs `country`, include it in `export_state` too (add `"country": self.country`). Do that now.

- [ ] **Step 4: Add `country` to `export_state`** and run

Edit `export_state` to include `"country": self.country`. Run:
`python3 -m pytest tests/test_eufy_cloud.py -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "feat(eufy_cloud): client skeleton, headers, state export/import"
```

---

## Task 6: API base resolution + request helper (mocked)

**Files:**
- Modify: `HA/custom_components/eufy_privacy/eufy_cloud.py`
- Test: `HA/tests/test_eufy_cloud.py`

- [ ] **Step 1: Write the failing test** (append; add `from unittest import mock` at top of test file)

```python
def test_resolve_api_base(monkeypatch):
    client = ec_lib.EufyCloudClient(country="IT", email="a@b.c", password="pw")

    def fake_get(url, headers=None, timeout=None):
        m = mock.Mock()
        m.json.return_value = {"data": {"domain": "security-app-eu.eufylife.com"}}
        m.status_code = 200
        return m

    monkeypatch.setattr(client._session, "get", fake_get)
    base = client.resolve_api_base()
    assert base == "https://security-app-eu.eufylife.com"
    assert client.api_base == base
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest tests/test_eufy_cloud.py -k resolve_api_base -v`
Expected: FAIL.

- [ ] **Step 3: Implement** (append to client)

```python
    # --- HTTP ---
    def resolve_api_base(self) -> str:
        for ep in (f"v1/{EP_DOMAIN.format(country=self.country)}",
                   EP_DOMAIN.format(country=self.country)):
            try:
                r = self._session.get(f"{DOMAIN_BASE}/{ep}", headers=self._headers(), timeout=15)
                dom = (r.json().get("data") or {}).get("domain")
                if dom:
                    self.api_base = dom if dom.startswith("http") else f"https://{dom}"
                    return self.api_base
            except Exception:
                continue
        self.api_base = "https://security-app-eu.eufylife.com"
        return self.api_base

    def _post(self, endpoint: str, data: dict) -> dict:
        if not self.api_base:
            self.resolve_api_base()
        r = self._session.post(
            f"{self.api_base}/{endpoint}", json=data, headers=self._headers(), timeout=20
        )
        if r.status_code != 200:
            raise EufyCloudError(f"HTTP {r.status_code} su {endpoint}: {r.text[:200]}")
        return r.json()

    def _shared_secret(self) -> bytes:
        return ecdh_shared_secret(self.client_private_key, self.server_public_key)

    def _decrypt(self, b64: str):
        import json as _json
        return _json.loads(decrypt_api_data(b64, self._shared_secret()))
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m pytest tests/test_eufy_cloud.py -v`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "feat(eufy_cloud): api base resolution + post/decrypt helpers"
```

---

## Task 7: login() — success, 2FA, captcha (mocked)

**Files:**
- Modify: `HA/custom_components/eufy_privacy/eufy_cloud.py`
- Test: `HA/tests/test_eufy_cloud.py`

The login encrypts the password with the **bootstrap** server key, posts to
`login_sec`, and branches on `code`. We model the result as a small object.

- [ ] **Step 1: Write the failing test** (append)

```python
def _make_login_response(client, code, data):
    # cifra email come fa il server (con la chiave bootstrap → shared del client)
    return {"code": code, "msg": "x", "data": data}


def test_login_success(monkeypatch):
    client = ec_lib.EufyCloudClient(country="IT", email="a@b.c", password="pw",
                                    api_base="https://x")
    key = client._shared_secret()
    enc_email = ec_lib.encrypt_api_data("a@b.c", key)

    def fake_post(endpoint, data):
        assert endpoint == ec_lib.EP_LOGIN
        assert isinstance(data["password"], str) and data["password"]  # cifrata
        return _make_login_response(client, 0, {
            "auth_token": "TOK", "token_expires_at": 9999999999,
            "user_id": "uid", "email": enc_email, "nick_name": "n",
            "server_secret_info": {"public_key": client.server_public_key},
        })

    monkeypatch.setattr(client, "_post", fake_post)
    res = client.login()
    assert res.status == "ok"
    assert client.token == "TOK"
    assert client.user_id == "uid"


def test_login_needs_2fa(monkeypatch):
    client = ec_lib.EufyCloudClient(country="IT", email="a@b.c", password="pw", api_base="https://x")
    monkeypatch.setattr(client, "_post", lambda e, d: {"code": ec_lib.CODE_NEED_VERIFY_CODE,
                                                       "data": {"auth_token": "TMP", "token_expires_at": 1}})
    monkeypatch.setattr(client, "_send_verify_code", lambda: None)
    res = client.login()
    assert res.status == "need_2fa"


def test_login_needs_captcha(monkeypatch):
    client = ec_lib.EufyCloudClient(country="IT", email="a@b.c", password="pw", api_base="https://x")
    monkeypatch.setattr(client, "_post", lambda e, d: {"code": ec_lib.CODE_NEED_CAPTCHA,
                                                       "data": {"captcha_id": "CID", "item": "BASE64IMG"}})
    res = client.login()
    assert res.status == "need_captcha"
    assert res.captcha_id == "CID"
    assert res.captcha_image == "BASE64IMG"
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest tests/test_eufy_cloud.py -k login -v`
Expected: FAIL.

- [ ] **Step 3: Implement** (append; add `from .const import EP_LOGIN, EP_SEND_VERIFY, CODE_OK, CODE_NEED_VERIFY_CODE, CODE_NEED_CAPTCHA, CODE_CAPTCHA_ERROR` with the same try/except fallback)

```python
@dataclass
class LoginResult:
    status: str  # "ok" | "need_2fa" | "need_captcha" | "error"
    captcha_id: str = ""
    captcha_image: str = ""
    message: str = ""


class _LoginMixin:  # documentazione: questi metodi vivono dentro EufyCloudClient
    pass
```
Add these methods **inside `EufyCloudClient`**:
```python
    def _login_payload(self, *, verify_code=None, captcha=None) -> dict:
        # password cifrata con la chiave server BOOTSTRAP
        boot_key = ecdh_shared_secret(self.client_private_key, SERVER_PUBLIC_KEY_BOOTSTRAP)
        data = {
            "ab": self.country,
            "client_secret_info": {"public_key": self._client_public_key_hex()},
            "enc": 0,
            "email": self.email,
            "password": encrypt_api_data(self.password, boot_key),
            "time_zone": 3600000,
            "transaction": str(int(time.time() * 1000)),
        }
        if verify_code:
            data["verify_code"] = verify_code
        elif captcha:
            data["captcha_id"] = captcha[0]
            data["answer"] = captcha[1]
        return data

    def _send_verify_code(self):
        try:
            self._post(EP_SEND_VERIFY, {"message_type": 0, "transaction": str(int(time.time() * 1000))})
        except Exception:
            pass

    def _apply_login_success(self, data: dict):
        ssi = (data.get("server_secret_info") or {}).get("public_key")
        if ssi:
            self.server_public_key = ssi
        self.user_id = data.get("user_id")
        self.token = data.get("auth_token")
        self.token_expiration = data.get("token_expires_at")

    def _do_login(self, *, verify_code=None, captcha=None) -> "LoginResult":
        resp = self._post(EP_LOGIN, self._login_payload(verify_code=verify_code, captcha=captcha))
        code = resp.get("code")
        data = resp.get("data") or {}
        if code == CODE_OK:
            self._apply_login_success(data)
            return LoginResult(status="ok")
        if code == CODE_NEED_VERIFY_CODE:
            self.token = data.get("auth_token")
            self.token_expiration = data.get("token_expires_at")
            self._send_verify_code()
            return LoginResult(status="need_2fa")
        if code in (CODE_NEED_CAPTCHA, CODE_CAPTCHA_ERROR):
            return LoginResult(status="need_captcha",
                               captcha_id=data.get("captcha_id", ""),
                               captcha_image=data.get("item", ""))
        return LoginResult(status="error", message=str(resp.get("msg")))

    def login(self) -> "LoginResult":
        if not self.api_base:
            self.resolve_api_base()
        return self._do_login()

    def submit_2fa(self, code: str) -> "LoginResult":
        return self._do_login(verify_code=code)

    def submit_captcha(self, captcha_id: str, answer: str) -> "LoginResult":
        return self._do_login(captcha=(captcha_id, answer))
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m pytest tests/test_eufy_cloud.py -v`
Expected: PASS (10 tests).

- [ ] **Step 5: Commit**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "feat(eufy_cloud): login with 2FA/captcha branches"
```

---

## Task 8: list_cameras() and set_privacy() (mocked)

**Files:**
- Modify: `HA/custom_components/eufy_privacy/eufy_cloud.py`
- Test: `HA/tests/test_eufy_cloud.py`

- [ ] **Step 1: Write the failing test** (append)

```python
def test_list_cameras_decrypts_and_parses(monkeypatch):
    client = ec_lib.EufyCloudClient(country="IT", email="a@b.c", password="pw", api_base="https://x")
    key = client._shared_secret()
    enc = ec_lib.encrypt_api_data(
        '[{"device_name":"Box","device_sn":"SN1","station_sn":"SN1",'
        '"device_model":"T8419","params":[{"param_type":1035,"param_value":"0"}]}]', key)
    monkeypatch.setattr(client, "_post", lambda e, d: {"code": 0, "data": enc})
    cams = client.list_cameras()
    assert cams[0].name == "Box"
    assert cams[0].privacy_on is False


def test_set_privacy_sends_string_values(monkeypatch):
    client = ec_lib.EufyCloudClient(country="IT", email="a@b.c", password="pw", api_base="https://x")
    cam = ec_lib.EufyCamera("Box", "SN1", "SN1", "T8419", False, {1035, 6250})
    captured = {}

    def fake_post(endpoint, data):
        captured["endpoint"] = endpoint
        captured["data"] = data
        return {"code": 0, "msg": "ok"}

    monkeypatch.setattr(client, "_post", fake_post)
    client.set_privacy(cam, True)
    assert captured["endpoint"] == ec_lib.EP_SET_PARAMS
    assert {"param_type": 1035, "param_value": "1"} in captured["data"]["params"]
    assert {"param_type": 6250, "param_value": "1"} in captured["data"]["params"]
    assert captured["data"]["device_sn"] == "SN1"


def test_set_privacy_raises_on_non_zero_code(monkeypatch):
    client = ec_lib.EufyCloudClient(country="IT", email="a@b.c", password="pw", api_base="https://x")
    cam = ec_lib.EufyCamera("Box", "SN1", "SN1", "T8419", False, {1035})
    monkeypatch.setattr(client, "_post", lambda e, d: {"code": 99, "msg": "no"})
    import pytest
    with pytest.raises(ec_lib.EufyCloudError):
        client.set_privacy(cam, True)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest tests/test_eufy_cloud.py -k "list_cameras or set_privacy" -v`
Expected: FAIL.

- [ ] **Step 3: Implement** (append to client; add `from .const import EP_DEVICE_LIST, EP_SET_PARAMS` to the fallback import)

```python
    def _device_list_body(self) -> dict:
        return {"device_sn": "", "num": 1000, "orderby": "", "page": 0,
                "station_sn": "", "time_zone": 3600000,
                "transaction": str(int(time.time() * 1000))}

    def list_cameras(self) -> list:
        resp = self._post(EP_DEVICE_LIST, self._device_list_body())
        if resp.get("code") != CODE_OK or not resp.get("data"):
            raise EufyCloudError(f"device_list fallita: code={resp.get('code')} msg={resp.get('msg')}")
        return parse_cameras(self._decrypt(resp["data"]))

    def set_privacy(self, camera, on: bool):
        params = build_privacy_params(on, camera.available_param_types or set(PRIVACY_PARAM_TYPES))
        body = {
            "device_sn": camera.serial,
            "station_sn": camera.station_sn,
            "params": params,
            "transaction": str(int(time.time() * 1000)),
        }
        resp = self._post(EP_SET_PARAMS, body)
        if resp.get("code") != CODE_OK:
            raise EufyCloudError(f"set privacy fallita: code={resp.get('code')} msg={resp.get('msg')}")
        return True
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m pytest tests/test_eufy_cloud.py -v`
Expected: PASS (13 tests).

- [ ] **Step 5: Commit**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "feat(eufy_cloud): list_cameras + set_privacy"
```

---

## Task 9: ensure_token() auto re-login on expiry

**Files:**
- Modify: `HA/custom_components/eufy_privacy/eufy_cloud.py`
- Test: `HA/tests/test_eufy_cloud.py`

- [ ] **Step 1: Write the failing test** (append)

```python
def test_ensure_token_relogins_when_expired(monkeypatch):
    client = ec_lib.EufyCloudClient(country="IT", email="a@b.c", password="pw", api_base="https://x",
                                    token="OLD", token_expiration=1)  # scaduto (1970)
    calls = {"login": 0}

    def fake_login():
        calls["login"] += 1
        client.token = "NEW"
        client.token_expiration = 9999999999
        return ec_lib.LoginResult(status="ok")

    monkeypatch.setattr(client, "login", fake_login)
    client.ensure_token()
    assert calls["login"] == 1
    assert client.token == "NEW"
    # con token valido non rifà login
    client.ensure_token()
    assert calls["login"] == 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest tests/test_eufy_cloud.py -k ensure_token -v`
Expected: FAIL.

- [ ] **Step 3: Implement** (append to client)

```python
    def ensure_token(self) -> "LoginResult | None":
        now = int(time.time())
        if self.token and self.token_expiration and now < int(self.token_expiration) - 60:
            return None
        return self.login()
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m pytest tests/test_eufy_cloud.py -v`
Expected: PASS (14 tests).

- [ ] **Step 5: Commit**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "feat(eufy_cloud): ensure_token auto re-login"
```

---

## Task 10: Standalone CLI (manual integration test against the real account)

**Files:**
- Create: `HA/cli.py`

- [ ] **Step 1: Write the CLI**

Create `HA/cli.py`:
```python
"""CLI standalone pure-Python: elenco camere e toggle privacy (sostituto di list.js/privacy.js).

Uso:
  python3 cli.py list
  python3 cli.py privacy <NOME|SERIAL> <on|off>

Credenziali: variabili d'ambiente EUFY_EMAIL / EUFY_PASSWORD (country IT).
Persistenza token: file ./eufy_state.json.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "custom_components", "eufy_privacy"))
import eufy_cloud as ec  # noqa: E402

STATE_FILE = os.path.join(os.path.dirname(__file__), "eufy_state.json")


def _client():
    email = os.environ["EUFY_EMAIL"]
    password = os.environ["EUFY_PASSWORD"]
    state = {}
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            state = json.load(f)
    client = ec.EufyCloudClient.from_state(email, password, state) if state else \
        ec.EufyCloudClient(country="IT", email=email, password=password)
    res = client.ensure_token()
    if res and res.status == "need_2fa":
        client.submit_2fa(input("Codice 2FA email: ").strip())
    elif res and res.status == "need_captcha":
        print(f"Captcha image (base64) id={res.captcha_id}:\n{res.captcha_image[:80]}...")
        client.submit_captcha(res.captcha_id, input("Captcha: ").strip())
    with open(STATE_FILE, "w") as f:
        json.dump(client.export_state(), f)
    return client


def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    client = _client()
    cams = client.list_cameras()
    if sys.argv[1] == "list":
        for c in cams:
            print(f"- {c.name:15} {c.serial}  model={c.model}  "
                  f"privacy={'ON' if c.privacy_on else 'off'}")
        return
    if sys.argv[1] == "privacy" and len(sys.argv) == 4:
        query, action = sys.argv[2], sys.argv[3]
        cam = next((c for c in cams if query in (c.name, c.serial)), None)
        if not cam:
            print(f"Camera '{query}' non trovata"); return
        client.set_privacy(cam, action == "on")
        print(f"Privacy {action.upper()} inviata a {cam.name}")
        return
    print(__doc__)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Manual test — list**

Run (use the known-good credentials from `list.js`):
```bash
cd /mnt/c/Simone/Eufy/HA
EUFY_EMAIL='your-email@example.com' EUFY_PASSWORD='your-password' python3 cli.py list
```
Expected: prints Box, CamCantina, CamBici with privacy state. If it asks for 2FA/captcha, complete it once (then `eufy_state.json` caches the token).

- [ ] **Step 3: Manual test — privacy round-trip on Box**

```bash
EUFY_EMAIL='your-email@example.com' EUFY_PASSWORD='your-password' python3 cli.py privacy Box on
# verifica fisica, poi:
EUFY_EMAIL='your-email@example.com' EUFY_PASSWORD='your-password' python3 cli.py privacy Box off
```
Expected: Box enters then leaves privacy (matches the spike).

- [ ] **Step 4: Add `eufy_state.json` to ignore + commit**

```bash
cd /mnt/c/Simone/Eufy && printf 'HA/eufy_state.json\nHA/.venv/\n__pycache__/\n' >> .gitignore
git add HA/cli.py .gitignore && git commit -m "feat(eufy_cloud): standalone CLI + manual validation"
```

---

## Task 11: HA manifest + const wiring

**Files:**
- Create: `HA/custom_components/eufy_privacy/manifest.json`

- [ ] **Step 1: Write `manifest.json`**

```json
{
  "domain": "eufy_privacy",
  "name": "Eufy Privacy (pure-Python)",
  "version": "0.1.0",
  "documentation": "https://github.com/local/eufy_privacy",
  "issue_tracker": "https://github.com/local/eufy_privacy/issues",
  "dependencies": [],
  "codeowners": [],
  "requirements": [],
  "iot_class": "cloud_polling",
  "config_flow": true
}
```
> `requirements` is empty: `requests` and `cryptography` are already in HA core.

- [ ] **Step 2: Commit**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "feat(eufy_privacy): HA manifest"
```

---

## Task 12: Coordinator (manual refresh only)

**Files:**
- Create: `HA/custom_components/eufy_privacy/coordinator.py`

- [ ] **Step 1: Write `coordinator.py`**

```python
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
```

- [ ] **Step 2: Sanity import check** (no HA installed locally → just byte-compile)

Run: `cd /mnt/c/Simone/Eufy/HA && python3 -m py_compile custom_components/eufy_privacy/coordinator.py`
Expected: no output (compiles). HA-specific imports are resolved only on the RPi.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "feat(eufy_privacy): manual-refresh coordinator"
```

---

## Task 13: `__init__.py` — entry setup/unload

**Files:**
- Modify: `HA/custom_components/eufy_privacy/__init__.py`

- [ ] **Step 1: Write `__init__.py`**

```python
"""Integrazione eufy_privacy: setup della config entry."""
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, CONF_COUNTRY, Platform
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import EufyPrivacyCoordinator
from .eufy_cloud import EufyCloudClient

PLATFORMS = [Platform.SWITCH, Platform.BUTTON]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = entry.data
    state = dict(entry.data.get("state", {}))
    state.setdefault("country", data.get(CONF_COUNTRY, "IT"))
    client = EufyCloudClient.from_state(data[CONF_EMAIL], data[CONF_PASSWORD], state)

    coordinator = EufyPrivacyCoordinator(hass, client)
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # persisti eventuale token rinnovato
    new_state = await hass.async_add_executor_job(client.export_state)
    if new_state != data.get("state"):
        hass.config_entries.async_update_entry(
            entry, data={**data, "state": new_state}
        )
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unloaded
```

- [ ] **Step 2: Byte-compile**

Run: `cd /mnt/c/Simone/Eufy/HA && python3 -m py_compile custom_components/eufy_privacy/__init__.py`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "feat(eufy_privacy): entry setup/unload"
```

---

## Task 14: Switch entity (privacy, assumed_state)

**Files:**
- Create: `HA/custom_components/eufy_privacy/switch.py`

- [ ] **Step 1: Write `switch.py`**

```python
"""Switch privacy: uno per camera. assumed_state (nessun polling automatico)."""
from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        EufyPrivacySwitch(coordinator, serial) for serial in coordinator.data
    )


class EufyPrivacySwitch(CoordinatorEntity, SwitchEntity):
    _attr_assumed_state = True
    _attr_has_entity_name = True
    _attr_name = "Privacy"
    _attr_icon = "mdi:eye-off"

    def __init__(self, coordinator, serial: str):
        super().__init__(coordinator)
        self._serial = serial
        self._attr_unique_id = f"{serial}_privacy"
        self._optimistic = None

    @property
    def _camera(self):
        return self.coordinator.data.get(self._serial)

    @property
    def device_info(self) -> DeviceInfo:
        cam = self._camera
        return DeviceInfo(
            identifiers={(DOMAIN, self._serial)},
            name=cam.name if cam else self._serial,
            manufacturer="Eufy",
            model=cam.model if cam else None,
        )

    @property
    def is_on(self) -> bool | None:
        if self._optimistic is not None:
            return self._optimistic
        cam = self._camera
        return cam.privacy_on if cam else None

    async def async_turn_on(self, **kwargs) -> None:
        await self._set(True)

    async def async_turn_off(self, **kwargs) -> None:
        await self._set(False)

    async def _set(self, on: bool) -> None:
        cam = self._camera
        if cam is None:
            return
        await self.hass.async_add_executor_job(self.coordinator.client.set_privacy, cam, on)
        self._optimistic = on
        self.async_write_ha_state()

    def _handle_coordinator_update(self) -> None:
        # dopo un refresh reale, abbandona lo stato ottimistico
        self._optimistic = None
        super()._handle_coordinator_update()
```

- [ ] **Step 2: Byte-compile**

Run: `cd /mnt/c/Simone/Eufy/HA && python3 -m py_compile custom_components/eufy_privacy/switch.py`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "feat(eufy_privacy): privacy switch entity"
```

---

## Task 15: Button entity (update_now)

**Files:**
- Create: `HA/custom_components/eufy_privacy/button.py`

- [ ] **Step 1: Write `button.py`**

```python
"""Button 'Aggiorna stato' (update_now): legge lo stato privacy dal cloud on-demand."""
from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        EufyPrivacyUpdateNowButton(coordinator, serial) for serial in coordinator.data
    )


class EufyPrivacyUpdateNowButton(ButtonEntity):
    _attr_has_entity_name = True
    _attr_name = "Aggiorna stato"
    _attr_icon = "mdi:refresh"

    def __init__(self, coordinator, serial: str):
        self._coordinator = coordinator
        self._serial = serial
        self._attr_unique_id = f"{serial}_update_now"

    @property
    def device_info(self) -> DeviceInfo:
        cam = self._coordinator.data.get(self._serial)
        return DeviceInfo(
            identifiers={(DOMAIN, self._serial)},
            name=cam.name if cam else self._serial,
            manufacturer="Eufy",
            model=cam.model if cam else None,
        )

    async def async_press(self) -> None:
        await self._coordinator.async_request_refresh()
```

- [ ] **Step 2: Byte-compile**

Run: `cd /mnt/c/Simone/Eufy/HA && python3 -m py_compile custom_components/eufy_privacy/button.py`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "feat(eufy_privacy): update_now button entity"
```

---

## Task 16: Config flow (user / 2fa / captcha / reauth)

**Files:**
- Create: `HA/custom_components/eufy_privacy/config_flow.py`
- Create: `HA/custom_components/eufy_privacy/strings.json`
- Create: `HA/custom_components/eufy_privacy/translations/it.json`

- [ ] **Step 1: Write `config_flow.py`**

```python
"""Config flow per eufy_privacy: login con 2FA e captcha."""
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, CONF_COUNTRY

from .const import DOMAIN
from .eufy_cloud import EufyCloudClient

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
        result = await self.hass.async_add_executor_job(fn)
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
```
> `trust_device` may not be strictly required; add a minimal implementation to `eufy_cloud.py`
> (Task 16b) so this call exists. If it errors, it is caught best-effort.

- [ ] **Step 1b: Add `trust_device` to the client** (`eufy_cloud.py`)

Append to `EufyCloudClient`:
```python
    def trust_device(self):
        """Best-effort: marca questo device come fidato per evitare 2FA futuri."""
        try:
            self._post("v1/app/trust_device/add", {
                "verify_code": "",
                "transaction": str(int(time.time() * 1000)),
            })
        except Exception:
            pass
```
Then verify the lib still passes: `cd /mnt/c/Simone/Eufy/HA && python3 -m pytest -q`. Expected: PASS (14).

- [ ] **Step 2: Write `strings.json`**

```json
{
  "config": {
    "step": {
      "user": {
        "title": "Account Eufy",
        "data": {"email": "Email", "password": "Password", "country": "Paese"}
      },
      "2fa": {"title": "Verifica 2FA", "data": {"code": "Codice ricevuto via email"}},
      "captcha": {
        "title": "Captcha",
        "description": "Risolvi il captcha (id: {captcha_id})",
        "data": {"answer": "Risposta captcha"}
      }
    },
    "error": {"auth_failed": "Autenticazione fallita. Controlla le credenziali."},
    "abort": {"already_configured": "Account già configurato."}
  }
}
```

- [ ] **Step 3: Write `translations/it.json`** (same content as `strings.json`)

Copy `strings.json` to `translations/it.json`:
```bash
cp custom_components/eufy_privacy/strings.json custom_components/eufy_privacy/translations/it.json
```

- [ ] **Step 4: Byte-compile config_flow**

Run: `cd /mnt/c/Simone/Eufy/HA && python3 -m py_compile custom_components/eufy_privacy/config_flow.py`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "feat(eufy_privacy): config flow (user/2fa/captcha) + strings"
```

---

## Task 17: Deploy to HA & end-to-end validation

**Files:** none (deployment + manual verification)

- [ ] **Step 1: Copy the integration to the RPi**

Copy `HA/custom_components/eufy_privacy/` to the RPi at `/config/custom_components/eufy_privacy/`
(via the Samba or SSH add-on). Example with SSH add-on:
```bash
scp -r HA/custom_components/eufy_privacy root@<HA_IP>:/config/custom_components/
```

- [ ] **Step 2: Restart HA & check logs**

Restart Home Assistant (Developer Tools → Restart, or `ha core restart`).
Check Settings → System → Logs for `eufy_privacy` errors. Expected: none.

- [ ] **Step 3: Add the integration**

Settings → Devices & Services → Add Integration → "Eufy Privacy (pure-Python)".
Enter email/password/country. Complete 2FA/captcha if prompted (once).
Expected: integration created, 3 devices (Box, CamCantina, CamBici), each with a
`Privacy` switch and an `Aggiorna stato` button.

- [ ] **Step 4: Functional test on Box**

- Press Box's **Aggiorna stato** → switch reflects current real privacy state.
- Toggle Box's **Privacy** switch ON → verify physically/in Eufy app that Box enters privacy.
- Toggle OFF → Box leaves privacy.
Expected: all behave as in the spike. If a non-T8419 model (e.g. CamBici, T8W11C)
doesn't toggle, run `node ../checkStatus.js` to confirm its privacy param id and
extend `PRIVACY_PARAM_TYPES` in `const.py`.

- [ ] **Step 5: Tag the working version**

```bash
cd /mnt/c/Simone/Eufy && git add HA && git commit -m "chore(eufy_privacy): v0.1.0 validated on HA" && git tag eufy_privacy-v0.1.0
```

---

## Self-Review notes

- **Spec coverage:** auth/login+2FA+captcha (Task 7,16), reuse-same-account (CLI Task 10, flow Task 16), one switch/camera (Task 14), `update_now` button instead of polling (Task 12,15), separate HA-agnostic lib (Tasks 1-9), persistence in entry (Task 5,13), error handling 401/network/write (Tasks 8,9,12,14), tests (Tasks 1-9), manual validation (Task 17), CLI standalone (Task 10). All covered.
- **Param-value-as-string** invariant is explicitly asserted in Task 8 test.
- **Open item carried into implementation:** confirm `CODE_NEED_VERIFY_CODE`/captcha numeric codes against `types.js` (Task 0 Step 3); confirm non-T8419 privacy param ids (Task 17 Step 4). Both are flagged, not silently assumed.
```
