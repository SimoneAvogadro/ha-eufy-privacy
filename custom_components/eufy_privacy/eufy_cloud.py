"""Client cloud Eufy pure-Python (sincrono). Nessun import di Home Assistant.

Implementa i soli metodi che servono: login (+2FA/captcha), trust device,
lista camere, set privacy. Crittografia ECDH(prime256v1)+AES-256-CBC.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass, field

import requests

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import padding as _padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from .const import (
        BASE_HEADERS, DOMAIN_BASE,
        EP_DOMAIN, EP_LOGIN, EP_SEND_VERIFY, EP_TRUST_ADD,
        EP_DEVICE_LIST, EP_SET_PARAMS, EP_STATION_LIST, EP_DSK_KEYS,
        SERVER_PUBLIC_KEY_BOOTSTRAP,
        CODE_OK, CODE_NEED_VERIFY_CODE, CODE_NEED_CAPTCHA, CODE_CAPTCHA_ERROR,
        PARAM_DEVS_SWITCH, PARAM_PRIVACY_6250, PRIVACY_PARAM_TYPES,
    )
except ImportError:  # esecuzione come modulo standalone (test/CLI)
    from const import (
        BASE_HEADERS, DOMAIN_BASE,
        EP_DOMAIN, EP_LOGIN, EP_SEND_VERIFY, EP_TRUST_ADD,
        EP_DEVICE_LIST, EP_SET_PARAMS, EP_STATION_LIST, EP_DSK_KEYS,
        SERVER_PUBLIC_KEY_BOOTSTRAP,
        CODE_OK, CODE_NEED_VERIFY_CODE, CODE_NEED_CAPTCHA, CODE_CAPTCHA_ERROR,
        PARAM_DEVS_SWITCH, PARAM_PRIVACY_6250, PRIVACY_PARAM_TYPES,
    )

_LOGGER = logging.getLogger(__name__)


def ecdh_shared_secret(client_private_key_hex: str, server_public_key_hex: str) -> bytes:
    """Segreto condiviso ECDH (coordinata X, 32 byte) come Node `computeSecret`."""
    priv = ec.derive_private_key(
        int(client_private_key_hex, 16), ec.SECP256R1(), default_backend()
    )
    server_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), bytes.fromhex(server_public_key_hex)
    )
    return priv.exchange(ec.ECDH(), server_pub)


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
        # Fallback best-effort: il PKCS7 non torna (alcuni endpoint Eufy non
        # paddano in modo canonico). Sfilo gli ultimi out[-1] byte solo come
        # euristica; in caso di payload non-padded il taglio al primo \x00 e il
        # parse JSON a valle correggono. Non garantisce correttezza bit-perfetta.
        if out and 1 <= out[-1] <= 16:
            out = out[: -out[-1]]
    nul = out.find(b"\x00")
    if nul != -1:
        out = out[:nul]
    return out.decode("utf-8", errors="replace")


def is_privacy_on(params: dict) -> bool:
    """True se la privacy è attiva.

    6250 è l'indicatore di privacy AUTOREVOLE su T8419/T8W11C: quando la privacy
    è impostata da app, 6250="1" mentre 1035 (DeviceEnabled) resta "0". Per questo
    leggiamo 6250 PRIMA di 1035 (verificato leggendo i param grezzi dal cloud con
    Box in privacy: 1035="0", 6250="1"). 1035 resta come fallback per eventuali
    modelli che non espongono 6250. Default False.
    """
    for pt in (PARAM_PRIVACY_6250, PARAM_DEVS_SWITCH):
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


@dataclass
class EufyCamera:
    name: str
    serial: str
    station_sn: str
    model: str
    privacy_on: bool
    available_param_types: set[int] = field(default_factory=set)


def _params_dict(device: dict) -> dict:
    out = {}
    for p in device.get("params", []):
        try:
            out[int(p["param_type"])] = p.get("param_value")
        except (KeyError, ValueError, TypeError):
            continue
    return out


def parse_cameras(decrypted_device_list: list) -> list:
    """Estrae un EufyCamera per ogni dispositivo nella lista decrittata."""
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


# ── Funzioni di utilità ──────────────────────────────────────────────────────

def md5_hex(s: str) -> str:
    """Restituisce l'MD5 esadecimale di una stringa UTF-8."""
    return hashlib.md5(s.encode("utf-8")).hexdigest()


# ── Eccezione personalizzata ─────────────────────────────────────────────────

class EufyCloudError(Exception):
    """Errore durante la comunicazione con il cloud Eufy."""


class EufyAuthRequired(EufyCloudError):
    """Il re-login dopo un 401 richiede interazione (2FA/captcha): serve reauth."""

    def __init__(self, login_result=None):
        super().__init__("re-login richiede 2FA/captcha")
        self.login_result = login_result


# ── Risultato login ──────────────────────────────────────────────────────────

@dataclass
class LoginResult:
    status: str          # "ok" | "need_2fa" | "need_captcha" | "error"
    captcha_id: str = ""
    captcha_image: str = ""
    message: str = ""


# ── Client principale ────────────────────────────────────────────────────────

class EufyCloudClient:
    """Client sincrono per il cloud Eufy (login, lista camere, privacy)."""

    def __init__(
        self, country, email, password, *,
        openudid="", client_private_key=None, server_public_key=None,
        token=None, token_expiration=None, user_id=None, api_base=None,
    ):
        self.country = country.upper()
        self.email = email
        self.password = password
        # L'openudid identifica il "device" verso il cloud: il server rifiuta il
        # login (code 10000, "openudid is null") se manca. Se non fornito ne
        # genera uno casuale stabile (16 hex), poi persistito in export_state.
        self.openudid = openudid or secrets.token_hex(8)
        if client_private_key:
            self.client_private_key = client_private_key
        else:
            priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
            self.client_private_key = format(priv.private_numbers().private_value, "064x")
        self.server_public_key = server_public_key or SERVER_PUBLIC_KEY_BOOTSTRAP
        self.token = token
        self.token_expiration = token_expiration  # epoch seconds
        self.user_id = user_id
        self.api_base = api_base
        self._session = requests.Session()

    def _client_public_key_hex(self) -> str:
        """Punto pubblico non compresso (hex) derivato dalla chiave privata."""
        priv = ec.derive_private_key(
            int(self.client_private_key, 16), ec.SECP256R1(), default_backend()
        )
        return priv.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        ).hex()

    def _headers(self) -> dict:
        """Header HTTP con token e gtoken se disponibili."""
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
        """Esporta lo stato del client come dizionario serializzabile."""
        return {
            "country": self.country,
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
        """Ricrea il client da uno stato precedentemente esportato."""
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

    # ── Task 6: risoluzione base URL + helper post/decrypt ───────────────────

    def resolve_api_base(self) -> str:
        """Interroga il domain-endpoint per ottenere il server regionale."""
        for ep in (f"v1/{EP_DOMAIN.format(country=self.country)}",
                   EP_DOMAIN.format(country=self.country)):
            try:
                r = self._session.get(
                    f"{DOMAIN_BASE}/{ep}", headers=self._headers(), timeout=15
                )
                dom = (r.json().get("data") or {}).get("domain")
                if dom:
                    self.api_base = dom if dom.startswith("http") else f"https://{dom}"
                    return self.api_base
            except Exception:
                continue
        self.api_base = "https://security-app-eu.eufylife.com"
        return self.api_base

    def _post(self, endpoint: str, data: dict, _allow_relogin: bool = True) -> dict:
        """POST JSON verso l'API Eufy; risolve la base se mancante.

        Su 401 (token invalidato lato server, es. sessione spodestata) prova un
        re-login automatico e ritenta una volta. Se il re-login richiede
        2FA/captcha solleva EufyAuthRequired (→ reauth flow in UI).
        """
        if not self.api_base:
            self.resolve_api_base()
        r = self._session.post(
            f"{self.api_base}/{endpoint}", json=data,
            headers=self._headers(), timeout=20,
        )
        if r.status_code == 401 and _allow_relogin and endpoint != EP_LOGIN:
            _LOGGER.info("Token Eufy invalidato (401 su %s): eseguo re-login.", endpoint)
            res = self.login()
            if res.status == "ok":
                return self._post(endpoint, data, _allow_relogin=False)
            raise EufyAuthRequired(res)
        if r.status_code != 200:
            raise EufyCloudError(f"HTTP {r.status_code} su {endpoint}: {r.text[:200]}")
        return r.json()

    def _shared_secret(self) -> bytes:
        """Segreto ECDH condiviso tra la chiave client e quella server corrente."""
        return ecdh_shared_secret(self.client_private_key, self.server_public_key)

    def _decrypt(self, b64: str):
        """Decifra e decodifica JSON dalla risposta cifrata dell'API."""
        return json.loads(decrypt_api_data(b64, self._shared_secret()))

    # ── Task 7: login con gestione 2FA e captcha ─────────────────────────────

    def _login_payload(self, *, verify_code=None, captcha=None) -> dict:
        """Costruisce il payload di login con password cifrata."""
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
        """Richiede l'invio del codice di verifica (best-effort)."""
        try:
            self._post(EP_SEND_VERIFY, {
                "message_type": 0,
                "transaction": str(int(time.time() * 1000)),
            })
        except Exception as err:  # best-effort: il server spesso invia comunque il codice
            _LOGGER.warning("Invio codice di verifica fallito (best-effort): %s", err)

    def _apply_login_success(self, data: dict):
        """Applica i dati di sessione dalla risposta di login."""
        ssi = (data.get("server_secret_info") or {}).get("public_key")
        if ssi:
            self.server_public_key = ssi
        self.user_id = data.get("user_id")
        self.token = data.get("auth_token")
        self.token_expiration = data.get("token_expires_at")

    def _do_login(self, *, verify_code=None, captcha=None) -> "LoginResult":
        """Esegue la chiamata di login e interpreta il codice risposta."""
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
            return LoginResult(
                status="need_captcha",
                captcha_id=data.get("captcha_id", ""),
                captcha_image=data.get("item", ""),
            )
        return LoginResult(status="error", message=str(resp.get("msg")))

    def login(self) -> "LoginResult":
        """Login iniziale: risolve la base URL se necessario."""
        if not self.api_base:
            self.resolve_api_base()
        return self._do_login()

    def submit_2fa(self, code: str) -> "LoginResult":
        """Invia il codice 2FA ricevuto via SMS."""
        return self._do_login(verify_code=code)

    def submit_captcha(self, captcha_id: str, answer: str) -> "LoginResult":
        """Invia la risposta al CAPTCHA."""
        return self._do_login(captcha=(captcha_id, answer))

    def trust_device(self):
        """Best-effort: marca questo device come fidato per evitare 2FA futuri."""
        try:
            self._post(EP_TRUST_ADD, {
                "verify_code": "",
                "transaction": str(int(time.time() * 1000)),
            })
        except Exception as err:  # best-effort: incide solo sui 2FA futuri
            _LOGGER.debug("trust_device fallito (best-effort): %s", err)

    # ── Task 8: lista camere e impostazione privacy ──────────────────────────

    def _device_list_body(self) -> dict:
        """Corpo della richiesta per ottenere la lista dispositivi."""
        return {
            "device_sn": "", "num": 1000, "orderby": "", "page": 0,
            "station_sn": "", "time_zone": 3600000,
            "transaction": str(int(time.time() * 1000)),
        }

    def list_cameras(self) -> list:
        """Recupera e decodifica la lista delle telecamere dall'API.

        `code != 0` è un errore vero. Invece `code == 0` con dati vuoti è uno
        stato VALIDO: l'account non ha (ancora) telecamere visibili/condivise →
        ritorna [] senza errori (l'integrazione si configura con 0 entità).
        """
        resp = self._post(EP_DEVICE_LIST, self._device_list_body())
        if resp.get("code") != CODE_OK:
            raise EufyCloudError(
                f"device_list fallita: code={resp.get('code')} msg={resp.get('msg')}"
            )
        data = resp.get("data")
        if not data:
            _LOGGER.warning(
                "Nessuna telecamera visibile per questo account Eufy "
                "(device_list vuota). Verifica la condivisione dei dispositivi."
            )
            return []
        return parse_cameras(self._decrypt(data))

    def set_privacy(self, camera, on: bool):
        """Imposta la modalità privacy sulla telecamera indicata."""
        params = build_privacy_params(on, camera.available_param_types or set(PRIVACY_PARAM_TYPES))
        body = {
            "device_sn": camera.serial,
            "station_sn": camera.station_sn,
            "params": params,
            "transaction": str(int(time.time() * 1000)),
        }
        resp = self._post(EP_SET_PARAMS, body)
        if resp.get("code") != CODE_OK:
            raise EufyCloudError(
                f"set privacy fallita: code={resp.get('code')} msg={resp.get('msg')}"
            )
        return True

    # ── Input per il toggle privacy via P2P (PPCS) ───────────────────────────

    def station_list(self) -> list:
        """Lista stazioni (per il P2P). `data` è cifrata → _decrypt.

        Ogni stazione espone p2p_did, app_conn, ip_addr, station_sn e
        member.admin_user_id, necessari per stabilire la sessione P2P.
        """
        resp = self._post(EP_STATION_LIST, {
            "device_sn": "", "num": 1000, "orderby": "", "page": 0,
            "station_sn": "", "time_zone": 3600000,
            "transaction": str(int(time.time() * 1000)),
        })
        if resp.get("code") != CODE_OK:
            raise EufyCloudError(f"station_list fallita: code={resp.get('code')} msg={resp.get('msg')}")
        data = resp.get("data")
        return self._decrypt(data) if data else []

    def get_dsk_keys(self, station_sn: str) -> tuple:
        """Chiave DSK per il lookup P2P (scade ~30 min). Risposta NON cifrata."""
        resp = self._post(EP_DSK_KEYS, {
            "invalid_dsks": {station_sn: ""},
            "station_sns": [station_sn],
            "transaction": str(int(time.time() * 1000)),
        })
        if resp.get("code") != CODE_OK:
            raise EufyCloudError(f"get_dsk_keys fallita: code={resp.get('code')} msg={resp.get('msg')}")
        for k in (resp.get("data") or {}).get("dsk_keys", []):
            if k.get("station_sn") == station_sn:
                return k.get("dsk_key"), k.get("expiration")
        raise EufyCloudError(f"DSK key non trovata per {station_sn}")

    def toggle_privacy_p2p(self, camera, on: bool, channel: int = 0) -> bool:
        """Commuta la privacy via P2P/PPCS (il cloud NON comanda la camera).

        Recupera p2p_did/app_conn/admin_user_id da station_list e la DSK key,
        poi apre una sessione P2P e invia il comando enable/disable. Sincrono.
        """
        try:
            from .p2p_session import P2PSession, decode_p2p_cloud_ips
        except ImportError:
            from p2p_session import P2PSession, decode_p2p_cloud_ips
        station_sn = camera.station_sn or camera.serial
        station = next(
            (s for s in self.station_list() if s.get("station_sn") == station_sn), None
        )
        if not station:
            raise EufyCloudError(f"stazione {station_sn} non trovata per il P2P")
        dsk, _exp = self.get_dsk_keys(station_sn)
        cloud_ips = decode_p2p_cloud_ips(station["app_conn"])
        admin = station["member"]["admin_user_id"]
        session = P2PSession(station_sn, station["p2p_did"], dsk, admin, cloud_ips, channel=channel)
        try:
            session.connect()
            if not session.set_privacy(on):
                raise EufyCloudError("comando privacy P2P non confermato (nessun ACK)")
        finally:
            session.close()
        return True

    # ── Task 9: rinnovo automatico del token ─────────────────────────────────

    def ensure_token(self):
        """Esegue il re-login se il token è assente o scaduto (margine 60 s)."""
        now = int(time.time())
        if self.token and self.token_expiration and now < int(self.token_expiration) - 60:
            return None
        return self.login()
