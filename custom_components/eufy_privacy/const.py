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

# Header di default replicati VERBATIM da eufy-security-client (device di test
# tedesco). Non devono coincidere col paese dell'account: il cloud li ignora di
# fatto e lo spike ha funzionato proprio con questi valori. Non "correggerli".
BASE_HEADERS = {
    "App_version": "v4.6.0_1630",
    "Os_type": "android",
    "Os_version": "31",
    "Phone_model": "ONEPLUS A3003",
    "Net_type": "wifi",
    "Mnc": "02",   # Vodafone DE — placeholder upstream, non legato all'account
    "Mcc": "262",  # Germania — idem, lasciare invariato
    "Sn": "75814221ee75",
    "Model_type": "PHONE",
    "Cache-Control": "no-cache",
    "Timezone": "GMT+01:00",
}

# Codici risposta login — valori verificati da ResponseErrorCode in
# eufy-security-client/build/http/types.js e types.d.ts
# CODE_WHATEVER_ERROR = 0      → risposta OK (nessun errore)
# CODE_NEED_VERIFY_CODE = 26052 → richiesto codice 2FA via SMS
# LOGIN_NEED_CAPTCHA = 100032   → richiesto CAPTCHA prima del login
# LOGIN_CAPTCHA_ERROR = 100033  → risposta CAPTCHA errata
CODE_OK = 0
CODE_NEED_VERIFY_CODE = 26052
CODE_NEED_CAPTCHA = 100032
CODE_CAPTCHA_ERROR = 100033
