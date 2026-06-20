"""Test del port pure-Python di decode_image (thumbnail evento cifrata dalla cam).

I valori attesi sono VETTORI DI RIFERIMENTO generati dalla lib JS eufy-security-client
(node -e ... su build/http/utils.js), cosi' il port e' validato byte-per-byte contro
l'originale, non solo contro se stesso.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "custom_components", "eufy_privacy"))

import eufy_cloud as ec_lib

# Vettori generati da: node -e '... u.getImageKey(...) ...' (vedi git history / piano)
P2P_DID = "ABCD-123456789-EFGH"
SERIAL = "T8000P0000000000"   # serial fittizio (NON un device reale)
CODE = "AB12345678"

ENCRYPTED_IMAGE_HEX = (
    "6575667973656375726974790054383030305030303030303030303030004142313233343536373800c8"
    "e4c574dd17e34842bc53330b1dcc87b9fd1de09308f2b0d6e900b21bc3cecb23e077abb10be0a58c41d3"
    "a130c105d8ae7af537a6de2bed3c74baa8f8055ffc69e12673c794bdab6ff068a8996bdcd7187de0eb70"
    "bbaf98f27898c0863ee6455f3a15f1d0bc841691e0465cfebc2ebdbe5b57fd2cb445d4b60151b4113246"
    "efb25ca9b37c21dc1cf1b6971df7148958c4cdb4311047dca15250b961381c2c08d1d0183fabf5454b81"
    "7bb282a31b658d9cb062c127199efaf29c0a6e03ba0c221ae23e48040520f7ebeff11290b093d3c7a0fc"
    "531d27692ffa65a72abd5f7d8f46d10a766cae8eed9566b2e4a17d196cbdf38677c7f6ed6f5c6644c8d4"
    "bd330b030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d"
    "141b222930"
)
EXPECTED_BODY_HEX = (
    "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b22"
    "2930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a4148"
    "4f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e"
    "757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d94"
    "9ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3ba"
    "c1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0"
    "e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff06"
    "0d141b222930"
)


def test_get_id_suffix_matches_js():
    assert ec_lib.get_id_suffix(P2P_DID) == 17


def test_get_image_base_code_matches_js():
    assert ec_lib.get_image_base_code(SERIAL, P2P_DID) == "T8000P000000000017"


def test_get_image_seed_matches_js():
    assert ec_lib.get_image_seed(P2P_DID, CODE) == "17917A033AAB2D9ABEF651A6A18C9A0E"


def test_get_image_key_matches_js():
    # 32 char hex uppercase; e' la chiave la cui prima meta' (16 ASCII) e' la chiave AES.
    assert ec_lib.get_image_key(SERIAL, P2P_DID, CODE) == "E67DF52AC581C81DCD481A73389162E7"


def test_decode_image_reverses_js_encrypted_image():
    img = bytes.fromhex(ENCRYPTED_IMAGE_HEX)
    out = ec_lib.decode_image(P2P_DID, img)
    assert out == bytes.fromhex(EXPECTED_BODY_HEX)


def test_decode_image_passthrough_when_not_eufy_header():
    # Una JPEG cloud non cifrata (header diverso da "eufysecurity") torna invariata.
    plain = b"\xff\xd8\xff\xe0" + b"not an eufy image, just jpeg bytes" * 4
    assert ec_lib.decode_image(P2P_DID, plain) == plain
