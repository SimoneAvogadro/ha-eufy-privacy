# Design — Integrazione Home Assistant `eufy_privacy` (pure-Python)

Data: 2026-06-16
Stato: approvato in brainstorming, in attesa di review dello spec scritto.

## 1. Obiettivo e contesto

Controllare la **modalità privacy** delle telecamere Eufy (elenco camere + on/off
privacy) da Home Assistant, **interamente in Python**, senza alcuna dipendenza da
Node.js né dal protocollo P2P.

Contesto rilevante:
- L'utente ha già l'integrazione `eufy_security` (fuatakgun) che dipende
  dall'addon Node `eufy-security-ws` (`127.0.0.1`). Questa integrazione vuole
  **sostituire quella dipendenza JS** per la sola funzione privacy.
- HA 2026.6.3, Raspberry Pi (supervised), `config_dir=/config`, country IT,
  timezone Europe/Rome, HACS installato.
- `cryptography` e `aiohttp` sono **già in HA core** → nessuna dipendenza extra.

### Fattibilità: già verificata con uno spike pure-Python

Prima del design abbiamo provato end-to-end (vedi `spike_eufy_cloud.py` nella root):
- **Auth** riusando il `cloud_token` cloud → OK.
- **Decrypt ECDH (prime256v1) + AES-256-CBC** delle risposte → OK.
- **Lista** camere via `v2/house/device_list` → OK (Box, CamCantina, CamBici).
- **Scrittura privacy** via `v1/app/upload_devs_params` → OK
  (`{"code":0,"msg":"Operazione completata."}`).
- **Effetto fisico confermato dall'utente**: il comando mette davvero la camera in
  privacy. Round-trip 0→1→0 verificato, camera ripristinata.

Dettaglio critico emerso: `param_value` va inviato come **stringa** (`"1"`), non
intero — con l'intero il gateway risponde `400` a corpo vuoto.

La libreria JS di bropat usa il P2P per `enableDevice`, ma **il cloud accetta lo
stesso comando**: nessun P2P necessario.

## 2. Decisioni di design (confermate)

- **A)** Una entità **`switch` per camera** = privacy on/off.
- **B)** **Nessun polling automatico.** Per ogni camera una entità **`button`**
  `update_now` che, premuta, legge lo stato privacy dal cloud e aggiorna lo switch.
  Lo switch è `assumed_state` (stato ottimistico tra un refresh e l'altro).
  Modella la richiesta "switch che a 1 aggiorna e torna a 0".
- **C)** La **libreria cloud** resta un modulo **separato e disaccoppiato da HA**
  (zero import di Home Assistant), pronto a diventare un package nel futuro monorepo.
- Tutto il codice vive in una **sottocartella `HA/`** del repo (futuro monorepo).
- **Auth**: login pure-Python con lo **stesso account** (`your-email@example.com`).
- Stile: commenti e log in **italiano** (coerente col resto del repo).

## 3. Architettura

Custom integration in `HA/custom_components/eufy_privacy/`, indipendente dall'addon
Node. Due strati netti:

```
HA/
  custom_components/
    eufy_privacy/
      __init__.py          # setup/unload entry, crea il client e il coordinator manuale
      manifest.json        # domain, requirements (cryptography già in core), config_flow
      const.py             # DOMAIN, costanti, param_type (1035, 6250), endpoint
      config_flow.py       # login, step 2FA, step captcha, reauth
      coordinator.py       # holder dello stato, refresh SOLO on-demand (update_interval=None)
      switch.py            # EufyPrivacySwitch (1 per camera, assumed_state)
      button.py            # EufyPrivacyUpdateNowButton (1 per camera)
      eufy_cloud.py        # LA LIB: client cloud pure-Python, nessun import HA
      strings.json
      translations/it.json
  docs/specs/2026-06-16-eufy-privacy-design.md
  tests/
    test_eufy_cloud.py     # unit test offline della lib
```

`eufy_cloud.py` è bundlato dentro l'integrazione (HA richiede componenti
self-contained) ma **non importa nulla di HA**, così l'estrazione futura in un
package del monorepo è banale.

## 4. La libreria `eufy_cloud.py` (i soli metodi che servono)

Client async basato su `aiohttp` + `cryptography`. API pubblica:

| Metodo | Scopo |
|---|---|
| `login()` | `v2/passport/login_sec`. Ritorna esito: `ok` / `need_2fa` / `need_captcha`. |
| `submit_2fa(code)` | Reinvio login con `verify_code`. |
| `submit_captcha(captcha_id, answer)` | Reinvio login con captcha. |
| `trust_device()` | `v1/app/trust_device/add` per evitare 2FA ai login successivi. |
| `refresh_token()` / gestione 401 | Re-login quando il token scade/невalido. |
| `list_devices()` | `v2/house/device_list` → lista camere con stato privacy. |
| `set_privacy(serial, station_sn, on: bool)` | `v1/app/upload_devs_params`. |

Dettagli crittografici (validati nello spike):
- **ECDH** prime256v1: chiave privata client (hex) + server public key.
  `shared = private.exchange(ECDH(), server_pub)` = 32 byte (coord. X), come Node.
- **Decrypt risposte**: AES-256-CBC, key=shared, iv=shared[:16], input base64;
  rimuovere padding PKCS7 / terminatore null prima del parse JSON.
- **Encrypt password** (login): simmetrico al decrypt, con la **SERVER_PUBLIC_KEY
  bootstrap** (`04c5c00c...`); la risposta fornisce il nuovo
  `server_secret_info.public_key` per le risposte seguenti.
- Header chiave: replica dei default di `eufy-security-client`
  (`App_version: v4.6.0_1630`, `Os_type: android`, …) + `Country`, `Language: it`,
  `Openudid`, `Timezone`, `X-Auth-Token`, `gtoken = md5(user_id)`.

Mapping stato privacy:
- `param_type` rilevanti: **1035** (`CMD_DEVS_SWITCH` / DeviceEnabled) e **6250**.
- Semantica validata su Box (T8419): `1035 == "0"` ⇒ privacy **OFF** (camera attiva);
  `1035 == "1"` ⇒ privacy **ON**.
- **Lettura**: `privacy_on = (params[1035] == "1")`, con fallback su `6250`.
- **Scrittura**: setta come **stringa** i param presenti tra `{1035, 6250}`
  (su Box entrambi funzionano; per altri modelli si verifica in implementazione).

Persistenza: il client espone/serializza il proprio stato (token, scadenza,
`clientPrivateKey`, `serverPublicKey`, user_id) così l'integrazione lo salva
nella **config entry** e non rifà login a ogni avvio.

## 5. Strato HA

### Config entry e setup
- 1 config entry = 1 account. `__init__.py` istanzia il client dai dati salvati,
  esegue **un** `list_devices()` iniziale per popolare lo stato, poi crea le
  piattaforme `switch` e `button`. Nessun `update_interval`.

### Coordinator
- `DataUpdateCoordinator` con `update_interval=None`: fa da contenitore dello stato
  delle camere. Si aggiorna **solo** via `async_request_refresh()` chiamato dai
  button `update_now` (e una volta al setup).

### Entità (per ogni camera)
- **`switch.eufy_privacy_<cam>`**: `is_on = privacy attiva`. `assumed_state = True`.
  - `async_turn_on` → `set_privacy(..., True)` → stato ottimistico ON.
  - `async_turn_off` → `set_privacy(..., False)` → stato ottimistico OFF.
  - In caso di errore (`code != 0` / eccezione): log + l'entità resta coerente al
    prossimo refresh.
- **`button.eufy_privacy_<cam>_update_now`**: `async_press` →
  `coordinator.async_request_refresh()` → aggiorna lo stato reale di quella camera
  (la `device_list` ritorna tutte le camere, quindi di fatto allinea tutte).
- Ogni camera è un **device** nel registry; switch e button vi sono collegati.

## 6. Config flow

- Step `user`: `email`, `password`, `country` (default `IT`).
- `login()`:
  - **ok** → crea entry salvando credenziali + token + chiavi ECDH + server pubkey;
    chiama `trust_device()`.
  - **need_2fa** → step `2fa` (codice email già inviato dal server) → re-login.
  - **need_captcha** → step `captcha` (mostra `item` base64, raccoglie risposta).
- **Reauth flow** su 401/scadenza: re-login; se richiede di nuovo 2FA, lo chiede in UI.

## 7. Gestione errori

- **401 / token scaduto** → re-login automatico con credenziali in entry. Se serve
  2FA → `reauth` in UI.
- **Conflitto di sessione (stesso account)**: app mobile e integrazione
  `eufy_security` esistente possono invalidare la sessione del plugin. Mitigazione:
  re-login al 401. Il design **no-polling** riduce di molto la frequenza delle
  chiamate e quindi il rischio. Limite documentato e accettato consapevolmente.
- **Errore di rete** → le entità diventano `unavailable`; il prossimo `update_now`
  ritenta.
- **Write fallita** → eccezione gestita, log esplicito in italiano.

## 8. Testing

- **TDD sulla lib `eufy_cloud.py`** (offline, senza rete):
  - round-trip `encrypt_api_data` ↔ `decrypt_api_data` con una coppia ECDH nota;
  - parsing di una `device_list` decifrata di esempio → lista camere + stato privacy;
  - mapping privacy (`1035`/`6250` → bool) nei due versi;
  - costruzione payload `upload_devs_params` con `param_value` **stringa**.
- **HTTP mockato** (`aioresponses`/monkeypatch) per: login ok / 2FA / captcha,
  `device_list`, `upload_devs_params`.
- **Validazione manuale**: deploy in `/config/custom_components/eufy_privacy/`,
  aggiunta via UI, toggle dello switch di **Box** e pressione `update_now`
  (la chiamata cloud sottostante è già provata end-to-end).

## 9. Sviluppo e deploy

- Sviluppo in `/mnt/c/Simone/Eufy/HA/`.
- Deploy: copia `HA/custom_components/eufy_privacy/` sul RPi in
  `/config/custom_components/` (Samba/SSH addon), riavvio HA, aggiunta integrazione.
- La lib resta usabile come **CLI standalone** (sostituto pure-Python di
  `list.js` / `privacy.js`).

## 10. Fuori scope (YAGNI, futuro)

- Card Lovelace custom "switch + tasto refresh" (mappa direttamente su
  `switch` + `button` già previsti qui).
- Estrazione della lib in un package del monorepo.
- Controlli Eufy diversi dalla privacy (guard mode, stream, ecc.).
- Refresh automatico/temporizzato (esplicitamente non voluto).
