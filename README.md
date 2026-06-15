# Eufy Privacy — Home Assistant integration

Two artifacts that together expose, in HA, a privacy switch for every Eufy
camera + a connectivity `binary_sensor` + the `eufy_privacy.set_privacy_mode`
service.

Updates are **real-time** (1–5 seconds) via FCM push from the Eufy cloud →
bridge → WebSocket → HA. No visible polling on the network.

```
<repo-root>/
├── hacs.json                   ← makes the repo installable via HACS (integration)
├── repository.yaml             ← makes the repo an add-on repository (bridge)
├── eufy-bridge/                ← Supervisor add-on (Node.js sidecar)
└── custom_components/
    └── eufy_privacy/           ← Python integration (installed by HACS)
```

> One repo, two distribution mechanisms: **HACS** installs the integration, the
> **add-on repository** installs the bridge. The user adds a single GitHub URL.

The bridge is mandatory because `eufy-security-client` is a Node.js library: on
HAOS it does not run inside the HA core container, so it lives in an add-on.

## How updates work

```
[Eufy mobile app / HomeBase]
        │  (FCM push, 1-5s)
        ▼
[eufy-security-client inside the Node.js bridge]
        │  emits a "device property changed" event
        ▼
[Bridge /events WebSocket]
        │  broadcasts JSON to connected clients
        ▼
[custom_components: EufyEventStream]
        │  apply_event_update(serial, …) on the coordinator
        ▼
[switch / binary_sensor in HA]  ← state updated
```

- **Push (primary)**: the library keeps a Firebase Cloud Messaging channel open
  to the Eufy cloud and receives property events virtually in real time. The
  bridge forwards them to HA over WebSocket.
- **Heartbeat (safety net)**: every 10 minutes the coordinator still runs a
  `GET /cameras` to recover any missed events (e.g. a brief WS drop).
  Configurable in `const.py` (`UPDATE_INTERVAL`).
- **Commands**: the switch and the `set_privacy_mode` service call REST
  `POST /cameras/{serial}/privacy`; the state update still arrives via push,
  there is no forced polling after the toggle.

## Privacy mode mapping

`eufy-security-client` 3.2 does **not** have `setPrivacyMode()` or
`isPrivacyModeEnabled()`. Privacy mode is the device's **`enabled` flag**,
driven by the station:

| Operation                          | Library API                          |
|----------------------------------- |------------------------------------- |
| Read privacy state                 | `!device.isEnabled()`                |
| Enable privacy (camera off)        | `station.enableDevice(device, false)`|
| Disable privacy (camera on)        | `station.enableDevice(device, true)` |

The bridge hides this inversion: the REST API exposes `privacyEnabled` as a
natural boolean (`true` = camera in privacy / off).

## Install the Bridge add-on

**Via add-on repository (recommended):**

1. In HA: **Settings → Add-ons → Add-on Store → ⋮ → Repositories**, paste
   `https://github.com/SimoneAvogadro/ha-eufy-privacy` and click **Add**.
2. The **"Eufy Bridge"** add-on shows up in the store under the new repository.
3. **Install** → **Start**. Leave `Start on boot` ON.
4. In the add-on log, look for:
   ```
   Eufy bridge listening on 0.0.0.0:8787
   Bridge token written to /data/bridge_token
   ```
5. **Get the token**: from the add-on shell, read `/data/bridge_token`. You'll
   use it in the next step.

<details><summary>Alternative: manual copy (local add-on)</summary>

1. **Copy** the `eufy-bridge/` folder into `/addons/` on HAOS
   (Samba/SSH/File Editor — the exact location depends on your setup).
2. **Settings → Add-ons → Add-on Store → ⋮ → Reload**. The add-on appears under
   **Local add-ons**.
3. **Install** → **Start**. Leave `Start on boot` ON.

</details>

The add-on:
- Does not publish ports on the host. It stays on the Supervisor internal network.
- Persists `persistent.json` (Eufy cloud token) and `bridge_token` in `/data`.
- Does not ask for Eufy credentials in its UI: it receives them via REST from the
  integration.

## Install the integration

**Via HACS (recommended):** HACS → ⋮ → **Custom repositories** → paste
`https://github.com/SimoneAvogadro/ha-eufy-privacy`, category **Integration** →
**Add** → search "Eufy Privacy" → **Download** → **Restart HA Core**. Then jump
to step 3.

<details><summary>Alternative: manual copy</summary>

1. **Copy** `custom_components/eufy_privacy/` into `/config/custom_components/`.
2. **Restart HA Core**.

</details>

3. **Settings → Devices & Services → Add Integration → "Eufy Privacy"**.
4. Fill in the form:
   - Eufy email / password
   - Country: `IT`
   - Language: `it`
   - Bridge URL: leave the default `http://local_eufy_bridge:8787`
     (if it's an add-on from a different repository the slug may change — check
     with `ha addons info`)
   - Bridge token: paste the contents of `/data/bridge_token`
5. **Submit**. If Eufy asks for CAPTCHA or 2FA: open the Eufy Security app on
   your phone, log in normally (to clear the CAPTCHA), then go back to HA and
   retry.

Once running you'll see one HA device per camera with:
- `switch.<camera_name>_privacy`
- `binary_sensor.<camera_name>_online`

## Service callable via API

`eufy_privacy.set_privacy_mode(serial, enabled)` is exposed automatically by HA
as:

```bash
curl -X POST \
  -H "Authorization: Bearer <long-lived-token>" \
  -H "Content-Type: application/json" \
  -d '{"serial":"T8410P1234567","enabled":true}' \
  http://homeassistant.local:8123/api/services/eufy_privacy/set_privacy_mode
```

The same service is available in **Developer Tools → Services** and in
automations.

## End-to-end verification

1. Add-on log: `Eufy bridge listening on …`, `WebSocket /events ready`, no
   `lastError`.
2. Bridge REST sanity: from the add-on shell
   ```bash
   TOKEN=$(cat /data/bridge_token)
   curl -H "X-Bridge-Token: $TOKEN" http://localhost:8787/cameras | jq .
   ```
   Returns an array with `privacyEnabled` for each camera.
3. Bridge WS sanity:
   ```bash
   wscat -c "ws://localhost:8787/events?token=$TOKEN"
   ```
   On connect a `{"type":"bridge_status",...}` must arrive immediately.
4. HA log filtered by `eufy_privacy`: `Connected to bridge events` must appear.
5. **Push from the mobile app**: open Eufy Security on your phone, enable privacy
   on a camera. In HA `Developer Tools → States` the matching switch flips to
   `on` **within 5 seconds**.
6. **Toggle from the switch UI**: the camera icon state changes on the mobile app
   within a few seconds and the HA switch stays in sync thanks to the return push
   (it doesn't wait for polling).
7. **REST service**: call `eufy_privacy.set_privacy_mode` as shown above; the
   switch state updates within 5s via push.
8. **WS reconnection**: stop and restart the add-on. In the HA log look for the
   backoff attempts (`WS connect failed … retrying in …s`) and then
   `Connected to bridge events` again within 60s.
9. **Eufy persistence**: the bridge reuses `persistent.json` and does not ask for
   the password again (until `cloud_token_expiration` — ~18 months).
10. **HA restart**: after restart, the coordinator does an initial GET and then
    immediately starts the WS stream.

## Future: snapshots

The bridge is already structured to accept `POST /cameras/:serial/snapshot`.
When it lands, it'll be enough to add an endpoint that calls
`station.startLivestream(device, ...)` (or the cloud HTTP API when available),
save a frame, and add a `camera` entity in the integration that returns the
image via `async_camera_image()`. None of this is implemented in V1.

## Diagnose for new models

If a model doesn't implement the standard `enabled` flag, the bridge exposes:

```bash
curl -H "X-Bridge-Token: ..." http://localhost:8787/diagnose/SERIAL_A/SERIAL_B
```

where A is in privacy and B is not (or vice versa). It reproduces the logic of
`checkStatus.js`: it compares the `rawProperties` and returns only the IDs with
differing values. From there you identify the correct `propertyId` and extend
the bridge with a model-specific fallback.
