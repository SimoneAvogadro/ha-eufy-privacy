"""CLI standalone pure-Python: diagnostica e test delle feature Eufy fuori da Home Assistant.

Uso:
  python3 cli.py list                              # elenca le camere
  python3 cli.py privacy <NOME|SERIAL> <on|off>    # toggle privacy (cloud)
  python3 cli.py listen                            # ascolta gli eventi push MQTT (gate Spike A)
  python3 cli.py image  <NOME|SERIAL> <pic_url> <FILE>  # scarica+decifra una thumbnail (Spike C)
  python3 cli.py snapshot <NOME|SERIAL> <FILE> [DUMP]  # frame fresco via P2P (Spike B; DUMP=cattura UDP)

Credenziali: variabili d'ambiente EUFY_EMAIL / EUFY_PASSWORD (country IT).
Persistenza token: file ./eufy_state.json (riusa il token per evitare login/2FA ripetuti).
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "custom_components", "eufy_privacy"))
import eufy_cloud as ec  # noqa: E402
import const as C  # noqa: E402

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


def _find_cam(cams, query):
    return next((c for c in cams if query in (c.name, c.serial)), None)


def _p2p_did_for(client, cam):
    """Recupera il p2p_did della station della camera (serve a decode_image)."""
    station_sn = cam.station_sn or cam.serial
    for s in client.station_list():
        if s.get("station_sn") == station_sn:
            return s.get("p2p_did")
    return None


def cmd_listen(client):
    """Si connette al broker push Eufy e stampa ogni messaggio + l'evento normalizzato.

    GATE Spike A: scatena un motion fisico e verifica se arriva un evento camera
    (kind=motion/person/...) su QUESTO account. Se SI -> MQTT e' la via; se NO -> serve FCM.
    """
    import socket
    import ssl
    import paho.mqtt.client as mqtt

    user_id = client.user_id
    if not user_id:
        print("Nessun user_id (login non riuscito?)")
        return
    print(f"[i] user_id={user_id}  broker={C.MQTT_HOST}:{C.MQTT_PORT}")

    # Workaround IP-rotto del NLB (visto negli esperimenti): isolato a questo processo CLI.
    _orig = socket.getaddrinfo

    def _gai(host, *a, **k):
        res = _orig(host, *a, **k)
        if host == C.MQTT_HOST:
            return [r for r in res if r[4][0] != "63.176.85.119"] or res
        return res
    socket.getaddrinfo = _gai

    cid = f"android_EufySecurity_{user_id}_{client.openudid or '0000000000000000'}"
    c = mqtt.Client(client_id=cid, protocol=mqtt.MQTTv311,
                    callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    c.username_pw_set(f"eufy_{user_id}", client.email)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c.tls_set_context(ctx)

    def on_connect(cl, u, f, rc, props=None):
        print(f"[CONNECT] rc={rc}")
        for t in (f"/phone/{user_id}/notice", f"/phone/{user_id}/#"):
            cl.subscribe(t, 1)
        print("[SUB] in ascolto (Ctrl-C per uscire)…", flush=True)

    def on_message(cl, u, msg):
        try:
            txt = msg.payload.decode("utf-8")
        except Exception:
            txt = msg.payload.hex()
        evt = ec.parse_push_message(msg.payload)
        marker = f"  >>> EVENTO kind={evt.kind} type={evt.event_type} serial={evt.serial} pic={'si' if evt.pic_url else 'no'}" if evt else "  (non-evento o non riconosciuto)"
        print(f"\n[MSG] {msg.topic}\n      {txt[:1200]}\n{marker}", flush=True)

    c.on_connect = on_connect
    c.on_message = on_message
    c.connect(C.MQTT_HOST, C.MQTT_PORT, 60)
    try:
        c.loop_forever()
    except KeyboardInterrupt:
        print("\n[exit]")


def cmd_image(client, query, pic_url, outfile):
    cams = client.list_cameras()
    cam = _find_cam(cams, query)
    if not cam:
        print(f"Camera '{query}' non trovata")
        return
    p2p_did = _p2p_did_for(client, cam)
    if not p2p_did:
        print(f"p2p_did non trovato per {cam.name}")
        return
    img = client.get_event_image(pic_url, p2p_did)
    with open(outfile, "wb") as f:
        f.write(img)
    is_jpeg = img[:2] == b"\xff\xd8"
    print(f"Scritti {len(img)} byte in {outfile}  "
          f"(header={img[:3].hex()}, {'JPEG ok' if is_jpeg else 'NON-JPEG?'})")


def cmd_snapshot(client, query, outfile, dump_path=None):
    cams = client.list_cameras()
    cam = _find_cam(cams, query)
    if not cam:
        print(f"Camera '{query}' non trovata")
        return
    # dump_path: salva i pacchetti UDP grezzi per il debug offline se il grab non funziona live.
    img = client.grab_snapshot_p2p(cam, dump_path=dump_path)
    with open(outfile, "wb") as f:
        f.write(img)
    print(f"Scritti {len(img)} byte in {outfile}"
          + (f"  (dump pacchetti: {dump_path})" if dump_path else ""))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    client = _client()
    if cmd == "list":
        for c in client.list_cameras():
            print(f"- {c.name:15} {c.serial}  model={c.model}  "
                  f"privacy={'ON' if c.privacy_on else 'off'}")
    elif cmd == "privacy" and len(sys.argv) == 4:
        cam = _find_cam(client.list_cameras(), sys.argv[2])
        if not cam:
            print(f"Camera '{sys.argv[2]}' non trovata")
            return
        client.set_privacy(cam, sys.argv[3] == "on")
        print(f"Privacy {sys.argv[3].upper()} inviata a {cam.name}")
    elif cmd == "listen":
        cmd_listen(client)
    elif cmd == "image" and len(sys.argv) == 5:
        cmd_image(client, sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "snapshot" and len(sys.argv) in (4, 5):
        cmd_snapshot(client, sys.argv[2], sys.argv[3],
                     dump_path=sys.argv[4] if len(sys.argv) == 5 else None)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
