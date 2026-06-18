"""Test dei builder byte-layout del client P2P (PPCS).

Vettori SINTETICI / costanti di protocollo (nessun dato reale di dispositivo).
La validazione byte-per-byte contro la cattura reale sta in validate_p2p.py (locale).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "custom_components", "eufy_privacy"))

import p2p_session as p  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402


def test_derive_key():
    # key = serial[-7:] + p2p_did[idx('-') : idx('-')+9]  -> 16 ASCII
    key = p.derive_key("XXXXXXXXX1234567", "ABC-987654-ZZ")
    assert key == b"1234567-987654-Z"
    assert len(key) == 16


def test_p2p_did_to_buffer():
    # part0 zero-padded a 8 + uint32BE(part1) + part2 zero-padded a 8 = 20 byte
    buf = p.p2p_did_to_buffer("ABC-1-XY")
    assert len(buf) == 20
    assert buf[:8] == b"ABC\x00\x00\x00\x00\x00"
    assert buf[8:12] == (1).to_bytes(4, "big")
    assert buf[12:] == b"XY\x00\x00\x00\x00\x00\x00"


def test_build_command_header():
    # P2PDataTypeHeader.DATA(d100) + uint16BE(seq) + "XZYH" + uint16LE(cmd)
    h = p.build_command_header(3, 1350)
    assert h == bytes.fromhex("d1000003") + b"XZYH" + (1350).to_bytes(2, "little")
    assert h.hex() == "d1000003585a59484605"


def test_build_void_payload_matches_protocol():
    # costante di protocollo verificata nella cattura reale (channel 255)
    assert p.build_void_payload(255).hex() == "000000000100ff000000"


def test_gatewayinfo_packet_constant():
    pkt = p.build_command_header(0, p.CMD_GATEWAYINFO) + p.build_void_payload(255)
    assert pkt.hex() == "d1000000585a59484c04000000000100ff000000"


def test_build_privacy_json():
    j = p.build_privacy_json("uid123", True, 0)
    assert j == '{"account_id":"uid123","cmd":6250,"mChannel":0,"mValue3":0,"payload":{"switch":1}}'
    assert '"switch":0}' in p.build_privacy_json("uid123", False, 0)


def test_string_type_payload_framing_and_roundtrip():
    key = b"0123456789abcdef"  # 16 byte
    value = p.build_privacy_json("uid123", True, 0)
    out = p.build_string_type_payload(p.ENC_TYPE, key, p.CMD_SET_PAYLOAD, value, 0)
    # framing: len(LE) + 0000 + 0100 + [ch=0, enc=1] + 0000 + cipher
    body_padded = p.padding_p2p(value.encode())
    assert out[:2] == len(body_padded).to_bytes(2, "little")
    assert out[2:4] == b"\x00\x00"
    assert out[4:6] == b"\x01\x00"
    assert out[6:8] == bytes([0, p.ENC_TYPE])
    assert out[8:10] == b"\x00\x00"
    cipher = out[10:]
    # round-trip: decifrando col key si riottiene il plaintext zero-pad
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    assert dec.update(cipher) + dec.finalize() == body_padded


def test_aes_ecb_known_vector():
    # sanity AES-128-ECB standard (NIST FIPS-197 appendix vettore noto)
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert p.encrypt_p2p(pt, key).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
