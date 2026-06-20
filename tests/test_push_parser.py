"""Test del parser eventi push (parse_push_message).

NB: le fixture replicano la STRUTTURA documentata da eufy-security-client
(push/service.js _normalizePushMessage: envelope con type/device_sn/station_sn e
inner `payload` con event_type/pic_url/push_count; varianti a chiavi corte a/c/k).
Vanno RI-VALIDATE su payload reali catturati con `cli.py listen` (gate Spike A):
il parser e' volutamente difensivo e ritorna None su cio' che non riconosce.
"""
import json, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "custom_components", "eufy_privacy"))
import eufy_cloud as ec


def test_motion_indoor_envelope():
    msg = {
        "type": 30, "device_sn": "T8000P0000000001", "station_sn": "T8000P0000000001",
        "event_time": 1700000000,
        "payload": {"event_type": 3101, "pic_url": "https://x/a.jpg", "push_count": 1},
    }
    e = ec.parse_push_message(json.dumps(msg))
    assert e is not None
    assert e.kind == "motion"
    assert e.event_type == 3101
    assert e.serial == "T8000P0000000001"
    assert e.station_sn == "T8000P0000000001"
    assert e.pic_url == "https://x/a.jpg"


def test_person_face_detection():
    msg = {"type": 30, "device_sn": "SN1", "payload": {"event_type": 3102, "pic_url": "u"}}
    e = ec.parse_push_message(msg)  # accetta anche dict gia' decodificato
    assert e is not None and e.kind == "person" and e.event_type == 3102


def test_short_keys_a_c_k():
    msg = {"type": 30, "device_sn": "SN1",
           "payload": {"a": 3105, "c": 2, "k": "CIPHER==", "pic_url": ""}}
    e = ec.parse_push_message(msg)
    assert e is not None
    assert e.kind == "sound" and e.event_type == 3105
    assert e.channel == 2 and e.cipher == "CIPHER=="


def test_inner_payload_as_json_string():
    inner = json.dumps({"event_type": 3106, "pic_url": "p", "push_count": 3})
    msg = {"device_sn": "SN1", "payload": inner}
    e = ec.parse_push_message(json.dumps(msg))
    assert e is not None and e.kind == "pet" and e.push_count == 3


def test_device_sn_falls_back_to_station_sn():
    msg = {"station_sn": "T8419X", "payload": {"event_type": 3101}}
    e = ec.parse_push_message(msg)
    assert e is not None and e.serial == "T8419X" and e.station_sn == "T8419X"


def test_non_camera_event_returns_none():
    # 9 = MODE_SWITCH, non e' un evento camera -> ignorato
    msg = {"type": 30, "device_sn": "SN1", "payload": {"event_type": 9, "content": "mode"}}
    assert ec.parse_push_message(json.dumps(msg)) is None


def test_missing_event_type_returns_none():
    msg = {"type": 30, "device_sn": "SN1", "payload": {"content": "ciao"}}
    assert ec.parse_push_message(msg) is None


def test_garbage_returns_none():
    assert ec.parse_push_message(b"not json at all") is None
    assert ec.parse_push_message("") is None
    assert ec.parse_push_message("[1,2,3]") is None  # JSON valido ma non un dict
