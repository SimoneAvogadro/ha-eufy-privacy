# ha-eufy-privacy

Integrazione **Home Assistant** in **puro Python** per controllare la *modalità privacy*
delle telecamere Eufy: elenca le camere e accende/spegne la privacy, **senza Node.js**
e **senza il protocollo P2P** — solo l'API cloud Eufy via HTTP.

Nasce per sostituire la dipendenza dall'add-on Node `eufy-security-ws` per la sola
funzione privacy.

## Come funziona

- Libreria cloud autonoma e disaccoppiata da HA (`custom_components/eufy_privacy/eufy_cloud.py`):
  login con 2FA/captcha, ECDH(prime256v1)+AES-256-CBC, lista camere, set privacy via
  `v1/app/upload_devs_params`. Usa solo `requests` + `cryptography` (entrambi già in HA core).
- Strato HA sottile: config flow, un coordinator **senza polling automatico**, e per ogni camera
  uno **switch Privacy** (`assumed_state`) più un **button "Aggiorna stato"** che fa il refresh
  dello stato on-demand.

> Nota tecnica: la modalità privacy si imposta scrivendo i param `1035` (`CMD_DEVS_SWITCH`)
> e/o `6250` con `param_value` come **stringa** (`"1"`/`"0"`). Con un intero il gateway
> risponde `400`. La libreria JS di bropat usa il P2P per questo, ma il cloud accetta lo
> stesso comando: nessun P2P necessario.

## Installazione

1. Copia `custom_components/eufy_privacy/` in `<config>/custom_components/` della tua
   istanza Home Assistant.
2. Riavvia Home Assistant.
3. Impostazioni → Dispositivi e servizi → Aggiungi integrazione → **Eufy Privacy (pure-Python)**.
4. Inserisci email, password e paese (default `IT`). Completa 2FA/captcha se richiesti
   (succede una volta: poi il dispositivo viene marcato come fidato).

Verrà creato un dispositivo per camera, con uno switch *Privacy* e un button *Aggiorna stato*.

## CLI standalone

La stessa libreria è usabile da riga di comando (sostituto pure-Python di `list.js`/`privacy.js`):

```bash
export EUFY_EMAIL='your-email@example.com'
export EUFY_PASSWORD='your-password'
python3 cli.py list
python3 cli.py privacy <NOME|SERIAL> <on|off>
```

Il token viene messo in cache in `eufy_state.json` (git-ignored) per evitare login ripetuti.

## Test

```bash
pip install -r requirements-test.txt
python3 -m pytest
```

## Limitazioni note (0.1.0)

- **Nessun reauth flow in UI**: se il token scade e serve un nuovo 2FA, le entità diventano
  `unavailable` (premi *Aggiorna stato* per ritentare; nel caso peggiore rimuovi e ri-aggiungi
  l'integrazione).
- **Conflitto di sessione (stesso account)**: l'app mobile Eufy o un'altra integrazione che
  usa lo stesso account possono invalidare la sessione. Il design senza polling riduce molto
  il problema.
- Effetto fisico validato end-to-end su modello **T8419**; per altri modelli verifica il
  param-id privacy con lo strumento diagnostico.

## Stato

`0.1.0` — libreria coperta da unit test e validata contro un account reale; lo strato HA è
verificato e va validato sulla propria istanza al primo deploy.
