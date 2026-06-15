# Eufy Privacy — integrazione Home Assistant

Due artefatti che, insieme, espongono in HA uno switch privacy per ogni
telecamera Eufy + un binary_sensor di connettività + il servizio
`eufy_privacy.set_privacy_mode`.

Aggiornamenti **in tempo reale** (1–5 secondi) via push FCM dal cloud Eufy →
bridge → WebSocket → HA. Niente polling visibile in rete.

```
<repo-root>/
├── hacs.json                   ← rende il repo installabile via HACS (integrazione)
├── repository.yaml             ← rende il repo un add-on repository (bridge)
├── eufy-bridge/                ← Supervisor Add-on (Node.js sidecar)
└── custom_components/
    └── eufy_privacy/           ← Integrazione Python (installata da HACS)
```

> Un solo repo, due meccanismi di distribuzione: **HACS** installa
> l'integrazione, l'**add-on repository** installa il bridge. L'utente aggiunge
> un solo URL GitHub.

Il bridge è obbligatorio perché `eufy-security-client` è una libreria Node.js:
su HAOS non gira dentro il container core di HA, quindi sta in un Add-on.

## Come funzionano gli aggiornamenti

```
[App mobile Eufy / HomeBase]
        │  (FCM push, 1-5s)
        ▼
[eufy-security-client nel bridge Node.js]
        │  emette evento "device property changed"
        ▼
[Bridge /events WebSocket]
        │  broadcast JSON ai client connessi
        ▼
[custom_components: EufyEventStream]
        │  apply_event_update(serial, …) sul coordinator
        ▼
[switch / binary_sensor in HA]  ← stato aggiornato
```

- **Push (primario)**: la libreria mantiene un canale Firebase Cloud Messaging
  sempre aperto verso il cloud Eufy e riceve gli eventi di proprietà
  praticamente in tempo reale. Il bridge li inoltra a HA via WebSocket.
- **Heartbeat (sicurezza)**: ogni 10 minuti il coordinator fa comunque un
  `GET /cameras` per ricucire eventuali eventi persi (es. WS caduta
  brevemente). Configurabile in `const.py` (`UPDATE_INTERVAL`).
- **Comandi**: lo switch e il servizio `set_privacy_mode` chiamano REST
  `POST /cameras/{serial}/privacy`; l'aggiornamento dello stato avviene
  comunque via push, non c'è polling forzato dopo il toggle.

## Mapping della modalità privacy

La libreria `eufy-security-client` 3.2 **non** ha `setPrivacyMode()` o
`isPrivacyModeEnabled()`. La modalità privacy è il **flag "enabled" del device**,
guidato dalla stazione:

| Operazione                          | API libreria                         |
|------------------------------------ |------------------------------------- |
| Leggere lo stato privacy            | `!device.isEnabled()`                |
| Attivare la privacy (camera off)    | `station.enableDevice(device, false)`|
| Disattivare la privacy (camera on)  | `station.enableDevice(device, true)` |

Il bridge nasconde questa inversione: l'API REST espone `privacyEnabled` come
boolean naturale (`true` = camera in privacy / spenta).

## Installare l'Add-on Bridge

**Via add-on repository (consigliato):**

1. In HA: **Settings → Add-ons → Add-on Store → ⋮ → Repositories**, incolla
   `https://github.com/SimoneAvogadro/ha-eufy-privacy` e **Add**.
2. L'add-on **"Eufy Bridge"** appare nello store sotto il repo appena aggiunto.
3. **Install** → **Start**. Lascia `Start on boot` ON.

<details><summary>Alternativa: copia manuale (local add-on)</summary>

1. **Copia** la cartella `eufy-bridge/` dentro `/addons/` su HAOS
   (Samba/SSH/File Editor — la posizione esatta dipende dal setup).
2. **Settings → Add-ons → Add-on Store → ⋮ → Reload**. L'add-on appare sotto
   **Local add-ons**.
3. **Install** → **Start**. Lascia `Start on boot` ON.

</details>
4. Nei log dell'add-on cerca:
   ```
   Eufy bridge listening on 0.0.0.0:8787
   Bridge token written to /data/bridge_token
   ```
5. **Recupera il token**: dalla shell dell'add-on (o `ha addons stdin eufy_bridge`
   non basta) leggi `/data/bridge_token`. Lo userai al passo seguente.

L'add-on:
- Non pubblica porte sull'host. Resta sulla rete interna del Supervisor.
- Persiste `persistent.json` (token cloud Eufy) e `bridge_token` in `/data`.
- Non chiede credenziali Eufy nella sua UI: le riceve via REST dall'integrazione.

## Installare l'integrazione

**Via HACS (consigliato):** HACS → ⋮ → **Custom repositories** → incolla
`https://github.com/SimoneAvogadro/ha-eufy-privacy`, categoria **Integration** → **Add** →
cerca "Eufy Privacy" → **Download** → **Riavvia HA Core**. Poi salta al punto 3.

<details><summary>Alternativa: copia manuale</summary>

1. **Copia** `custom_components/eufy_privacy/` dentro `/config/custom_components/`.
2. **Riavvia HA Core**.

</details>
3. **Settings → Devices & Services → Add Integration → "Eufy Privacy"**.
4. Compila il form:
   - Email / Password Eufy
   - Country: `IT`
   - Language: `it`
   - Bridge URL: lascia il default `http://local_eufy_bridge:8787`
     (se è un add-on di un altro repository può cambiare slug — verifica con
     `ha addons info`)
   - Bridge token: incolla il contenuto di `/data/bridge_token`
5. **Submit**. Se Eufy chiede CAPTCHA o 2FA: apri l'app Eufy Security sul
   telefono, fai login normalmente (così sbloccare il CAPTCHA), poi torna in
   HA e ritenta.

Una volta in piedi vedi un device HA per ogni telecamera con:
- `switch.<nome_camera>_privacy`
- `binary_sensor.<nome_camera>_online`

## Servizio richiamabile via API

`eufy_privacy.set_privacy_mode(serial, enabled)` è esposto automaticamente da
HA come:

```bash
curl -X POST \
  -H "Authorization: Bearer <long-lived-token>" \
  -H "Content-Type: application/json" \
  -d '{"serial":"T8410P1234567","enabled":true}' \
  http://homeassistant.local:8123/api/services/eufy_privacy/set_privacy_mode
```

Lo stesso servizio è disponibile in **Developer Tools → Services** e nelle
automazioni.

## Verifica end-to-end

1. Add-on log: `Eufy bridge listening on …`, `WebSocket /events ready`,
   nessuno `lastError`.
2. Sanity bridge REST: dalla shell dell'add-on
   ```bash
   TOKEN=$(cat /data/bridge_token)
   curl -H "X-Bridge-Token: $TOKEN" http://localhost:8787/cameras | jq .
   ```
   Restituisce un array con `privacyEnabled` per ogni camera.
3. Sanity bridge WS:
   ```bash
   wscat -c "ws://localhost:8787/events?token=$TOKEN"
   ```
   Al connect deve arrivare subito un `{"type":"bridge_status",...}`.
4. Log HA filtrato per `eufy_privacy`: deve comparire `Connected to bridge events`.
5. **Push da app mobile**: apri Eufy Security sul telefono, abilita la privacy
   su una camera. In HA `Developer Tools → States` lo switch corrispondente
   passa a `on` **entro 5 secondi**. (V1 con polling impiegava fino a 30s.)
6. **Toggle dallo switch UI**: lo stato dell'icona della camera cambia lato
   app mobile entro pochi secondi e lo switch HA resta in sync grazie al
   push di ritorno (non si aspetta il polling).
7. **Servizio REST**: chiama `eufy_privacy.set_privacy_mode` come mostrato
   sopra; lo stato del switch si aggiorna entro 5s via push.
8. **Riconnessione WS**: ferma e riavvia l'add-on. Nel log HA cerca i
   tentativi di backoff (`WS connect failed … retrying in …s`) e poi
   `Connected to bridge events` di nuovo entro 60s.
9. **Persistenza Eufy**: il bridge riusa `persistent.json` e non richiede di
   nuovo la password (fino a `cloud_token_expiration` — ~18 mesi).
10. **Riavvio HA**: dopo restart, il coordinator fa un GET iniziale e poi
    avvia subito lo stream WS.

## Futuro: snapshot

Il bridge è già strutturato per accogliere `POST /cameras/:serial/snapshot`.
Quando arriverà, basterà aggiungere un endpoint che invochi
`station.startLivestream(device, ...)` (o l'API HTTP cloud quando disponibile),
salvare un frame, e aggiungere una `camera` entity nell'integrazione che
restituisca l'immagine via `async_camera_image()`. Niente di tutto questo è
implementato in V1.

## Diagnose per modelli nuovi

Se un modello non implementa il flag `enabled` standard, il bridge espone:

```bash
curl -H "X-Bridge-Token: ..." http://localhost:8787/diagnose/SERIAL_A/SERIAL_B
```

dove A è in privacy e B no (o viceversa). Riproduce la logica di
`checkStatus.js`: confronta le `rawProperties` e restituisce solo gli ID
con valori diversi. Da lì si individua il `propertyId` corretto e si estende
il bridge con un fallback specifico per quel modello.
