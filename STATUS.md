# STATUS — Eufy Privacy for Home Assistant

> Snapshot as of **2026-06-15**, after promoting the work to a dedicated repo.
> Restart point for future sessions.

## What it is

Two artifacts that together expose, in HA, a **privacy switch** for every Eufy
camera + a connectivity **binary_sensor** + the `eufy_privacy.set_privacy_mode`
service, with **real-time push** updates (1–5 s) via FCM from the Eufy cloud.

```
<repo-root>/
├── STATUS.md                   ← this file
├── README.md                   ← install/verify guide (complete)
├── hacs.json                   ← HACS integration manifest
├── repository.yaml             ← add-on repository manifest
├── .gitignore
├── eufy-bridge/                ← Supervisor add-on (Node.js sidecar)
│   ├── config.yaml
│   ├── Dockerfile
│   └── src/{server.js, package.json}
└── custom_components/
    └── eufy_privacy/           ← Python integration (config_flow, coordinator, ...)
        ├── __init__.py, const.py, config_flow.py, coordinator.py
        ├── bridge.py, events.py, switch.py, binary_sensor.py
        ├── manifest.json, services.yaml, strings.json
        └── translations/{en.json, it.json}
```

### Why two pieces

`eufy-security-client` is a **Node.js** library: on HAOS it does not run inside
HA's core container. It therefore lives in an **add-on** (sidecar) exposing REST
+ WebSocket; the Python integration talks to it over the Supervisor internal
network. Same pattern as the official `eufy-security-ws` project.

## Runtime architecture

```
[Eufy mobile app / HomeBase]
        │  FCM push (1-5s)
        ▼
[eufy-security-client in the Node.js bridge]   ── emits "device property changed"
        │
        ▼
[Bridge /events WebSocket]   ── broadcasts JSON to clients
        │
        ▼
[custom_components: EufyEventStream]  ── apply_event_update(serial, …) on the coordinator
        │
        ▼
[switch / binary_sensor in HA]  ← state updated
```

- **Primary push** via FCM → WS.
- **Heartbeat** every 10 min (`UPDATE_INTERVAL` in `const.py`): GET `/cameras`
  to recover missed events.
- **Commands**: switch and service call `POST /cameras/{serial}/privacy`; state
  returns via push, no forced polling after the toggle.

### Privacy mapping (load-bearing)

`eufy-security-client` 3.2 does **not** have `setPrivacyMode()` /
`isPrivacyModeEnabled()`. Privacy is the device's `enabled` flag, driven by the
station:

| Operation                         | Library API                           |
|-----------------------------------|---------------------------------------|
| Read privacy state                | `!device.isEnabled()`                 |
| Enable privacy (camera off)       | `station.enableDevice(device, false)` |
| Disable privacy (camera on)       | `station.enableDevice(device, true)`  |

The bridge hides the inversion: the REST API exposes a natural `privacyEnabled`
(`true` = camera in privacy / off).

## Bridge API (server.js)

| Method | Path                      | Auth            | Notes |
|--------|---------------------------|-----------------|-------|
| GET    | `/healthz`                | none            | `{connected, lastError, initialised}` |
| POST   | `/init`                   | X-Bridge-Token  | Eufy login; 409 with `code` CAPTCHA/2FA/AUTH_FAILED |
| GET    | `/cameras`                | X-Bridge-Token  | snapshot array |
| GET    | `/cameras/:serial`        | X-Bridge-Token  | single camera |
| POST   | `/cameras/:serial/privacy`| X-Bridge-Token  | body `{enabled: bool}`; 501 if NOT_SUPPORTED |
| GET    | `/diagnose/:a/:b`         | X-Bridge-Token  | rawProperties diff (ports `checkStatus.js`) |
| WS     | `/events`                 | header or `?token=` | push: privacy_changed, battery_changed, devices_changed, bridge_status |

- Bridge token generated/persisted in `/data/bridge_token` (32-byte hex, mode 600).
- Single port shared HTTP+WS (default 8787), Supervisor internal network only.
- Persists Eufy `persistent.json` in `/data` (reuses cloud token, ~18 months).

## Packaging & distribution — DONE

Published as a **mono-repo** at
**https://github.com/SimoneAvogadro/ha-eufy-privacy**:

- `custom_components/eufy_privacy/` → distributed via **HACS** (integration
  category), driven by `hacs.json`.
- `eufy-bridge/` → distributed via **add-on repository**
  (Settings → Add-ons → Repositories), driven by `repository.yaml`.

The end user adds **one GitHub URL** to both HACS (as a custom repository) and
the add-on store, then does two installs.

| # | Item | Status |
|---|------|--------|
| 1 | Public GitHub repo | ✅ created (`SimoneAvogadro/ha-eufy-privacy`) |
| 2 | `hacs.json` in root | ✅ `{name, render_readme, homeassistant}` |
| 3 | `custom_components/` in root | ✅ standard layout |
| 4 | `manifest.json` `documentation` / `issue_tracker` | ✅ real URLs |
| 5 | `manifest.json` `codeowners` | ✅ `["@SimoneAvogadro"]` |
| 6 | Release / tag | ✅ tag `v0.1.0` + GitHub Release |
| 7 | `repository.yaml` for the add-on | ✅ present |

## Status: DONE

- [x] Complete Node.js add-on: REST + WS, token auth, clean shutdown, client-side backoff
- [x] Config flow with granular error handling (CAPTCHA / 2FA / bridge_token / unreachable / unknown)
- [x] Push-driven coordinator + reconciliation heartbeat; session re-init on expired Eufy token
- [x] WS consumer with exponential-backoff reconnection + post-reconnect refresh
- [x] Entities: `switch.<cam>_privacy`, `binary_sensor.<cam>_online`, per-camera device registry
- [x] `eufy_privacy.set_privacy_mode(serial, enabled)` service
- [x] `en` + `it` translations, `services.yaml`, `strings.json` (error keys aligned with config_flow)
- [x] `/diagnose` endpoint to identify the privacy property ID on new models
- [x] `iot_class: local_push` correct; `requirements: []` correct (logic in the bridge, not Python)
- [x] README with add-on + integration install + 10 end-to-end verification steps
- [x] Mono-repo packaging: `hacs.json`, `repository.yaml`, real `manifest.json` URLs, git + `v0.1.0` release
- [x] All docs in English

## Status: MISSING / known limits

- [ ] **Never verified end-to-end on a real HAOS** (the README verification is a checklist, not a report)
- [ ] No tests (Python or Node)
- [ ] Snapshot / `camera` entity: described in the README but **not implemented** in V1
- [ ] One instance per account (config flow with unique_id = email)
- [ ] Only the standard `enabled` property handled; non-standard models need `/diagnose` + a manual bridge extension

### Minor rough edges

- `Dockerfile` copies `src/package-lock.json*` but **the lockfile doesn't exist**
  → `npm ci` fails and falls back to `npm install` (works but not reproducible).
  Fix: commit a `package-lock.json` in `src/`.
- `eufy-bridge/Dockerfile` uses `node:20-alpine` directly (not an HA base image):
  fine as a local add-on, no bashio/s6 — acceptable for now.

## Proposed next steps

1. Commit a `package-lock.json` for the bridge (reproducible builds).
2. (Optional) first end-to-end test on a real HAOS + report.
3. (Future) snapshot / `camera` entity — new bridge endpoint + `camera` entity,
   no architecture change.
