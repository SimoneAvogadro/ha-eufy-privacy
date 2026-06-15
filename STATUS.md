# STATUS — Eufy Privacy per Home Assistant

> Snapshot dello stato al **2026-06-15**, scritto prima di promuovere il lavoro
> a progetto dedicato. Serve da punto di ripartenza una volta spostato tutto in
> un repo/folder separato.

## Cos'è

Due artefatti che insieme espongono in HA uno **switch privacy** per ogni
telecamera Eufy + un **binary_sensor** di connettività + il servizio
`eufy_privacy.set_privacy_mode`, con aggiornamenti **push in tempo reale**
(1–5 s) via FCM dal cloud Eufy.

```
HA/
├── STATUS.md                   ← questo file
├── README.md                   ← guida installazione/verifica (completa)
├── addon-eufy-bridge/          ← Supervisor Add-on (sidecar Node.js)
│   ├── config.yaml
│   ├── Dockerfile
│   └── src/{server.js, package.json}
└── custom_components/
    └── eufy_privacy/           ← integrazione Python (config_flow, coordinator, ...)
        ├── __init__.py, const.py, config_flow.py, coordinator.py
        ├── bridge.py, events.py, switch.py, binary_sensor.py
        ├── manifest.json, services.yaml, strings.json
        └── translations/{en.json, it.json}
```

### Perché due pezzi

`eufy-security-client` è una libreria **Node.js**: su HAOS non gira nel container
core di HA. Sta quindi in un **Add-on** (sidecar) che espone REST + WebSocket;
l'integrazione Python ci parla via rete interna del Supervisor. È lo stesso
pattern del progetto ufficiale `eufy-security-ws`.

## Architettura runtime

```
[App mobile Eufy / HomeBase]
        │  FCM push (1-5s)
        ▼
[eufy-security-client nel bridge Node.js]   ── emette "device property changed"
        │
        ▼
[Bridge /events WebSocket]   ── broadcast JSON ai client
        │
        ▼
[custom_components: EufyEventStream]  ── apply_event_update(serial, …) sul coordinator
        │
        ▼
[switch / binary_sensor in HA]  ← stato aggiornato
```

- **Push primario** via FCM → WS.
- **Heartbeat** ogni 10 min (`UPDATE_INTERVAL` in `const.py`): GET `/cameras`
  per ricucire eventi persi.
- **Comandi**: switch e servizio chiamano `POST /cameras/{serial}/privacy`;
  lo stato torna via push, niente polling forzato post-toggle.

### Mapping privacy (load-bearing)

`eufy-security-client` 3.2 **non** ha `setPrivacyMode()`/`isPrivacyModeEnabled()`.
La privacy è il flag `enabled` del device, guidato dalla stazione:

| Operazione                        | API libreria                          |
|-----------------------------------|---------------------------------------|
| Leggere stato privacy             | `!device.isEnabled()`                 |
| Attivare privacy (camera off)     | `station.enableDevice(device, false)` |
| Disattivare privacy (camera on)   | `station.enableDevice(device, true)`  |

Il bridge nasconde l'inversione: l'API REST espone `privacyEnabled` naturale
(`true` = camera in privacy / spenta).

## API del bridge (server.js)

| Metodo | Path                      | Auth            | Note |
|--------|---------------------------|-----------------|------|
| GET    | `/healthz`                | nessuna         | `{connected, lastError, initialised}` |
| POST   | `/init`                   | X-Bridge-Token  | login Eufy; 409 con `code` CAPTCHA/2FA/AUTH_FAILED |
| GET    | `/cameras`                | X-Bridge-Token  | snapshot array |
| GET    | `/cameras/:serial`        | X-Bridge-Token  | singola camera |
| POST   | `/cameras/:serial/privacy`| X-Bridge-Token  | body `{enabled: bool}`; 501 se NOT_SUPPORTED |
| GET    | `/diagnose/:a/:b`         | X-Bridge-Token  | diff rawProperties (porta `checkStatus.js`) |
| WS     | `/events`                 | header o `?token=` | push: privacy_changed, battery_changed, devices_changed, bridge_status |

- Token bridge generato/persistito in `/data/bridge_token` (32 byte hex, mode 600).
- Porta unica condivisa HTTP+WS (default 8787), solo rete interna Supervisor.
- Persiste `persistent.json` Eufy in `/data` (riusa token cloud, ~18 mesi).

## Stato: cosa è FATTO

- [x] Add-on Node.js completo: REST + WS, auth a token, shutdown pulito, backoff lato client
- [x] Config flow con gestione errori granulare (CAPTCHA / 2FA / bridge_token / unreachable / unknown)
- [x] Coordinator push-driven + heartbeat di reconciliation; re-init sessione su token Eufy scaduto
- [x] WS consumer con riconnessione a backoff esponenziale + refresh post-riconnessione
- [x] Entità: `switch.<cam>_privacy`, `binary_sensor.<cam>_online`, device registry per camera
- [x] Servizio `eufy_privacy.set_privacy_mode(serial, enabled)`
- [x] Traduzioni `en` + `it`, `services.yaml`, `strings.json` (chiavi errore allineate al config_flow)
- [x] Endpoint `/diagnose` per identificare il property ID privacy su modelli nuovi
- [x] `iot_class: local_push` corretto; `requirements: []` corretto (logica nel bridge, non in Python)
- [x] README con installazione add-on + integrazione + 10 step di verifica end-to-end

## Stato: cosa MANCA / limiti noti

- [ ] **Mai verificato end-to-end su un HAOS reale** (la verifica nel README è una checklist, non un report)
- [ ] Nessun test (Python o Node)
- [ ] Snapshot / `camera` entity: predisposto nel README ma **non implementato** in V1
- [ ] Una sola istanza per account (config flow con unique_id = email)
- [ ] Solo property `enabled` standard gestita; modelli non standard richiedono `/diagnose` + estensione manuale del bridge

### Bug/rough edge minori da sistemare

- `Dockerfile` copia `src/package-lock.json*` ma **il lockfile non esiste** →
  `npm ci` fallisce e cade su `npm install` (funziona ma non riproducibile).
  Fix: committare un `package-lock.json` in `src/`.
- `manifest.json` ha URL placeholder: `documentation`/`issue_tracker` =
  `https://github.com/local/eufy_privacy`, `codeowners: []`.
- `addon-eufy-bridge/Dockerfile` usa `node:20-alpine` diretto (non base image HA):
  ok come add-on locale, niente bashio/s6 — accettabile per ora.

## Promozione a progetto dedicato

**Autosufficiente**: il bridge reimplementa internamente la logica privacy e il
diagnose; **non importa nulla** da `list.js`/`checkStatus.js`/`privacy.js` del
repo padre. La cartella `HA/` può diventare la root di un nuovo repo as-is.
Nessun git inizializzato attualmente.

## Distribuzione — equivoco da chiarire

⚠️ **HACS NON distribuisce add-on.** Gestisce integrazioni, card Lovelace, temi,
ecc. Quindi:

- `custom_components/eufy_privacy/` → distribuibile via **HACS** (categoria integration)
- `addon-eufy-bridge/` → distribuibile SOLO via **add-on repository**
  (Settings → Add-ons → Repositories), meccanismo separato

L'utente finale farà **due installazioni**. È fattibile un **mono-repo** che fa
sia da add-on repository sia da repo HACS (pattern comune).

### Blocker per la sola integrazione su HACS

| # | Blocker | Stato | Serve |
|---|---------|-------|-------|
| 1 | Repo GitHub pubblico | nessun git | crearlo |
| 2 | `hacs.json` in root | assente | `{"name": "Eufy Privacy"}` |
| 3 | Struttura repo | `HA/custom_components/...` | `custom_components/` in root (o `content_in_root` in hacs.json) |
| 4 | `manifest.json` `documentation` / `issue_tracker` | placeholder `github.com/local/...` | URL reali |
| 5 | `manifest.json` `codeowners` | `[]` | almeno `["@<utente-github>"]` |
| 6 | Release/tag GitHub | nessuna | tag SemVer o default branch |

### Per l'add-on come repository

- `repository.yaml` (o `.json`) nella root del repo
- `config.yaml` add-on ok; valutare `build.yaml` con base image HA se si vuole build multi-arch gestita

## Prossimi passi proposti (al riavvio nel nuovo folder)

1. Inizializzare git nel nuovo folder, struttura mono-repo:
   ```
   <repo-root>/
   ├── hacs.json
   ├── repository.yaml          ← add-on repository
   ├── README.md
   ├── custom_components/eufy_privacy/
   └── eufy-bridge/             ← (ex addon-eufy-bridge)
   ```
2. Sistemare `manifest.json` (URL reali + codeowners).
3. Aggiungere `package-lock.json` al bridge e committarlo.
4. (Opzionale) primo test end-to-end su HAOS reale + report.
5. (Futuro) snapshot/camera entity.

**Dati che servono per chiudere il packaging:** username GitHub (per `codeowners`)
e URL del repo (per `documentation`/`issue_tracker`).
