import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "custom_components", "eufy_privacy"))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from unittest import mock
import eufy_cloud as ec_lib


def _keypair():
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_hex = priv.public_key().public_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.X962,
        format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.UncompressedPoint,
    ).hex()
    priv_hex = format(priv.private_numbers().private_value, "064x")
    return priv_hex, pub_hex


def test_ecdh_shared_secret_is_symmetric():
    a_priv, a_pub = _keypair()
    b_priv, b_pub = _keypair()
    s1 = ec_lib.ecdh_shared_secret(a_priv, b_pub)
    s2 = ec_lib.ecdh_shared_secret(b_priv, a_pub)
    assert s1 == s2
    assert len(s1) == 32


def test_encrypt_decrypt_roundtrip():
    a_priv, a_pub = _keypair()
    b_priv, b_pub = _keypair()
    key = ec_lib.ecdh_shared_secret(a_priv, b_pub)
    payload = '{"hello":"mondo","n":42}'
    enc = ec_lib.encrypt_api_data(payload, key)
    assert isinstance(enc, str)
    dec = ec_lib.decrypt_api_data(enc, ec_lib.ecdh_shared_secret(b_priv, a_pub))
    assert dec == payload


def test_is_privacy_on_reads_1035_then_6250():
    assert ec_lib.is_privacy_on({1035: "1"}) is True
    assert ec_lib.is_privacy_on({1035: "0"}) is False
    assert ec_lib.is_privacy_on({6250: "1"}) is True      # fallback
    assert ec_lib.is_privacy_on({}) is False               # default


def test_build_privacy_params_uses_strings_for_present_types():
    params = ec_lib.build_privacy_params(True, available_types={1035, 6250})
    assert {"param_type": 1035, "param_value": "1"} in params
    assert {"param_type": 6250, "param_value": "1"} in params
    assert len(params) == 2  # solo i type presenti, niente extra
    only = ec_lib.build_privacy_params(False, available_types={1035})
    assert only == [{"param_type": 1035, "param_value": "0"}]


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


# ── Task 5 ──────────────────────────────────────────────────────────────────

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


def test_openudid_generated_when_missing():
    # Il server rifiuta il login se Openudid è vuoto (code 10000): il client
    # deve generarne uno e includerlo negli header e nello stato persistito.
    client = ec_lib.EufyCloudClient(country="IT", email="a@b.c", password="pw")
    assert client.openudid
    assert len(client.openudid) == 16
    assert client._headers()["Openudid"] == client.openudid
    # stabile attraverso export/import dello stato
    client2 = ec_lib.EufyCloudClient.from_state("a@b.c", "pw", client.export_state())
    assert client2.openudid == client.openudid


# ── Task 6 ──────────────────────────────────────────────────────────────────

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


# ── Task 7 ──────────────────────────────────────────────────────────────────

def test_login_success(monkeypatch):
    client = ec_lib.EufyCloudClient(country="IT", email="a@b.c", password="pw",
                                    api_base="https://x")
    key = client._shared_secret()
    enc_email = ec_lib.encrypt_api_data("a@b.c", key)

    def fake_post(endpoint, data):
        assert endpoint == ec_lib.EP_LOGIN
        assert isinstance(data["password"], str) and data["password"]
        return {"code": 0, "msg": "x", "data": {
            "auth_token": "TOK", "token_expires_at": 9999999999,
            "user_id": "uid", "email": enc_email, "nick_name": "n",
            "server_secret_info": {"public_key": client.server_public_key},
        }}

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


# ── Task 8 ──────────────────────────────────────────────────────────────────

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


def test_list_cameras_empty_data_returns_empty(monkeypatch):
    # code==0 ma nessun dato (account senza camere condivise) => [] non errore
    client = ec_lib.EufyCloudClient(country="IT", email="a@b.c", password="pw", api_base="https://x")
    monkeypatch.setattr(client, "_post", lambda e, d: {"code": 0, "msg": "Operazione completata.", "data": ""})
    assert client.list_cameras() == []


def test_list_cameras_raises_on_error_code(monkeypatch):
    client = ec_lib.EufyCloudClient(country="IT", email="a@b.c", password="pw", api_base="https://x")
    monkeypatch.setattr(client, "_post", lambda e, d: {"code": 401, "msg": "no"})
    import pytest
    with pytest.raises(ec_lib.EufyCloudError):
        client.list_cameras()


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


# ── Task 9 ──────────────────────────────────────────────────────────────────

def test_ensure_token_relogins_when_expired(monkeypatch):
    client = ec_lib.EufyCloudClient(country="IT", email="a@b.c", password="pw", api_base="https://x",
                                    token="OLD", token_expiration=1)
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
    client.ensure_token()
    assert calls["login"] == 1
