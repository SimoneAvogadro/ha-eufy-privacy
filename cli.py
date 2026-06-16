"""CLI standalone pure-Python: elenco camere e toggle privacy (sostituto di list.js/privacy.js).

Uso:
  python3 cli.py list
  python3 cli.py privacy <NOME|SERIAL> <on|off>

Credenziali: variabili d'ambiente EUFY_EMAIL / EUFY_PASSWORD (country IT).
Persistenza token: file ./eufy_state.json (riusa il token per evitare login/2FA ripetuti).
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
        print(__doc__)
        return
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
            print(f"Camera '{query}' non trovata")
            return
        client.set_privacy(cam, action == "on")
        print(f"Privacy {action.upper()} inviata a {cam.name}")
        return
    print(__doc__)


if __name__ == "__main__":
    main()
