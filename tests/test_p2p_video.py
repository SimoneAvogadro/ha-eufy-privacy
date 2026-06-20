"""Test della crittografia/parsing video P2P per lo snapshot fresco (Spike B).

I vettori in tests/fixtures/rsa_video_vectors.json sono generati con la STESSA libreria
node-rsa usata dalla cam (eufy-security-client getNewRSAPrivateKey, scheme pkcs1, 1024 bit) +
AES-128-ECB: validano l'interop RSA-PKCS1v15 e AES del nostro port, non solo l'auto-consistenza.

NB: il grab end-to-end (socket P2P + riassemblaggio multi-pacchetto + ffmpeg) richiede una cam
reale e va validato live; qui si prova la parte deterministica (header video, decrypt, I-frame).
"""
import json, os, struct, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "custom_components", "eufy_privacy"))
import p2p_session as p2p

from cryptography.hazmat.primitives.serialization import load_pem_private_key

_VEC = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "rsa_video_vectors.json")))


def _priv():
    return load_pem_private_key(_VEC["privPem"].encode(), password=None)


def test_rsa_modulus_export_matches_wire_encryptkey():
    # encryptkey on-wire = modulo N (128 byte) hex, senza il byte di segno.
    assert p2p.rsa_public_modulus_hex(_priv()) == _VEC["nHexWire"]


def test_rsa_decrypt_aes_key_pkcs1():
    blob = bytes.fromhex(_VEC["cipherKey_hex"])
    assert p2p.rsa_decrypt_aes_key(_priv(), blob).hex() == _VEC["aesKey_hex"]


def test_decrypt_video_chunk_aes_ecb():
    aes_key = bytes.fromhex(_VEC["aesKey_hex"])
    enc = bytes.fromhex(_VEC["encFirst128_hex"])
    expected = bytes.fromhex(_VEC["payload_hex"])[:128]
    assert p2p.decrypt_video_chunk(aes_key, enc) == expected


def test_generate_rsa_keypair_shape():
    priv, encryptkey = p2p.generate_rsa_keypair()
    assert len(encryptkey) == 256                      # 128 byte di modulo in hex
    assert priv.key_size == 1024
    assert p2p.rsa_public_modulus_hex(priv) == encryptkey


def _build_video_frame(payload: bytes, sign_code: int) -> bytes:
    """Costruisce un buffer CMD_VIDEO_FRAME come lo manda la cam (con chiave AES RSA-wrapped)."""
    vdl = len(payload)
    head = (
        struct.pack("<I", vdl)            # [0:4] videoDataLength
        + b"\x01"                          # [4] isKeyFrame
        + b"\x01"                          # [5] streamType (H264)
        + struct.pack("<H", 7)             # [6:8] videoSeqNo
        + struct.pack("<H", 15)            # [8:10] fps
        + struct.pack("<H", 1920)          # [10:12] width
        + struct.pack("<H", 1080)          # [12:14] height
        + b"\x00" * 6                      # [14:20] timestamp
        + b"\x00\x00"                      # [20:22] padding
    )
    if sign_code > 0:
        enc_first = bytes.fromhex(_VEC["encFirst128_hex"])
        body = bytes.fromhex(_VEC["cipherKey_hex"]) + b"\x00" + enc_first + payload[128:]
    else:
        body = payload
    return head + body


def test_extract_video_frame_encrypted_roundtrip():
    payload = bytes.fromhex(_VEC["payload_hex"])          # 200 byte: 128 cifrati + 72 chiari
    data = _build_video_frame(payload, sign_code=1)
    meta, video = p2p.extract_video_frame(data, sign_code=1, private_key=_priv())
    assert meta["is_key_frame"] is True
    assert meta["stream_type"] == 1
    assert meta["video_seq_no"] == 7
    assert video == payload                                # decifra i primi 128 + concatena i 72 chiari


def test_extract_video_frame_plaintext_stream():
    payload = b"\x00\x00\x00\x01\x67abcdef plaintext nalus"
    data = _build_video_frame(payload, sign_code=0)
    meta, video = p2p.extract_video_frame(data, sign_code=0, private_key=None)
    assert video == payload


def test_find_start_code():
    assert p2p.find_start_code(b"\x00\x00\x01\x67rest") is True
    assert p2p.find_start_code(b"\x00\x00\x00\x01rest") is True
    assert p2p.find_start_code(b"\x00\x00\x01") is True
    assert p2p.find_start_code(b"\x01\x02\x03\x04") is False


def test_is_iframe():
    # NAL type valido a offset 3 o 4 (SPS=103, IDR=101, ecc.)
    assert p2p.is_iframe(b"\x00\x00\x00\x01\x67") is True   # [4]=103 SPS
    assert p2p.is_iframe(b"\x00\x00\x01\x65rest") is True   # [3]=101 IDR
    assert p2p.is_iframe(b"\x00\x00\x01\x41rest") is False  # [3]=65 non-IDR (P-frame)


def test_build_livestream_start_json():
    js = p2p.build_livestream_start_json("admin123", "deadbeef", streamtype=1)
    obj = json.loads(js)
    assert obj["commandType"] == 1000
    assert obj["data"]["accountId"] == "admin123"
    assert obj["data"]["encryptkey"] == "deadbeef"
    assert obj["data"]["streamtype"] == 1


def test_parse_udp_data_packet_video():
    part = b"\xaa\xbb\xcc"
    msg = (p2p.DATA + struct.pack(">H", len(part))
           + p2p.datatype_marker(p2p.P2P_DATATYPE_VIDEO)
           + struct.pack(">H", 42) + part)
    r = p2p.parse_udp_data_packet(msg)
    assert r is not None
    assert r["data_type"] == p2p.P2P_DATATYPE_VIDEO
    assert r["seq_no"] == 42
    assert r["part_data"] == part


def test_parse_udp_data_packet_rejects_non_data():
    assert p2p.parse_udp_data_packet(b"\xf1\xe0\x00\x00") is None  # PING, non DATA


def _msg_header(command_id, payload_len, sign_code=0, channel=0):
    return (p2p.MAGIC_WORD + struct.pack("<H", command_id) + struct.pack("<I", payload_len)
            + b"\x00\x00" + bytes([channel]) + bytes([sign_code]) + b"\x00" + b"\x00")


def test_parse_message_header():
    h = p2p.parse_message_header(_msg_header(1300, 200, sign_code=1, channel=3))
    assert h["magic_ok"] is True
    assert h["command_id"] == 1300
    assert h["bytes_to_read"] == 200
    assert h["channel"] == 3
    assert h["sign_code"] == 1


def test_build_ack_payload_matches_legacy_data_format():
    # Per il dataType DATA deve coincidere col formato gia' usato in _drain.
    assert p2p.build_ack_payload(p2p.P2P_DATATYPE_DATA, 7) == p2p.P2P_DATA_HEADER + struct.pack(">H", 1) + struct.pack(">H", 7)


def test_video_frame_assembler_single_and_split():
    payload = bytes(range(80))
    frame = _msg_header(p2p.CMD_VIDEO_FRAME, len(payload)) + payload
    # tutto in una parte
    a = p2p.VideoFrameAssembler()
    done = a.feed(frame)
    assert len(done) == 1
    hdr, fp = done[0]
    assert hdr["command_id"] == p2p.CMD_VIDEO_FRAME and fp == payload
    # spezzato in due parti (header+meta nella prima, resto nella seconda)
    b = p2p.VideoFrameAssembler()
    assert b.feed(frame[:30]) == []
    done2 = b.feed(frame[30:])
    assert len(done2) == 1 and done2[0][1] == payload
