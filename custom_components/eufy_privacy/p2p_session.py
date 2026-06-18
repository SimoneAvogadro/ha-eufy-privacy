"""Client PPCS (P2P) minimale pure-Python per commutare la privacy delle camere Eufy.

Il cloud HTTP NON comanda la camera (aggiorna solo il valore memorizzato): il comando
privacy viaggia in P2P/PPCS. Questo modulo invia il solo comando enable/disable
(privacy) replicando ciò che fa eufy-security-client (`station.enableDevice`).

Comando: CMD_SET_PAYLOAD (1350) string-payload, JSON
  {"account_id":<admin_user_id>,"cmd":6250,"mChannel":<ch>,"mValue3":0,"payload":{"switch":0|1}}
  switch=1 -> privacy ON, switch=0 -> privacy OFF.
Cifratura: AES-128-ECB (zero-pad a 16), chiave DERIVATA dal seriale + p2p_did
  key = serial[-7:] + p2p_did[p2p_did.index('-') : index('-')+9]  (16 ASCII, niente RSA).
encryptionType on-wire = 1.

Input (da HTTP cloud): serial, p2p_did, dsk_key, app_conn (o lista cloud IP), admin_user_id.
Pure stdlib + cryptography. Nessun import Home Assistant.
"""
from __future__ import annotations

import json
import socket
import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ── Tipi messaggio (p2p/types.js) ────────────────────────────────────────────
LOCAL_LOOKUP = b"\xf1\x30"
LOOKUP_WITH_KEY = b"\xf1\x26"
CHECK_CAM = b"\xf1\x41"
PING = b"\xf1\xe0"
PONG = b"\xf1\xe1"
DATA = b"\xf1\xd0"
ACK = b"\xf1\xd1"
END = b"\xf1\xf0"
LOOKUP_ADDR = b"\xf1\x40"
LOCAL_LOOKUP_RESP = b"\xf1\x41"
CAM_ID = b"\xf1\x42"

P2P_DATA_HEADER = b"\xd1\x00"   # P2PDataTypeHeader.DATA
MAGIC_WORD = b"XZYH"
CMD_SET_PAYLOAD = 1350
CMD_GATEWAYINFO = 1100
CMD_PRIVACY = 6250
ENC_TYPE = 1                    # encryptionType on-wire (verificato in cattura)

CLOUD_LOOKUP_TABLE = bytes.fromhex(
    "4959433db5bf6da347534f6165e371e9677f02030badb3892b2f35c16b8b95"
    "9711e5a70deff1050783fb9d3bc5c713171d1f2529d3df"
)


# ── Builder byte-layout (port 1:1 da p2p/utils.js) ───────────────────────────
def string_with_length(text: str | bytes, chunk: int = 128) -> bytes:
    b = text.encode() if isinstance(text, str) else text
    size = chunk if len(b) < chunk else ((len(b) + chunk - 1) // chunk) * chunk
    return b + b"\x00" * (size - len(b))


def padding_p2p(data: bytes, block: int = 16) -> bytes:
    size = block if len(data) < block else ((len(data) + block - 1) // block) * block
    return data + b"\x00" * (size - len(data))


def p2p_did_to_buffer(p2p_did: str) -> bytes:
    a = p2p_did.split("-")
    return string_with_length(a[0], 8) + struct.pack(">I", int(a[1])) + string_with_length(a[2], 8)


def derive_key(serial: str, p2p_did: str) -> bytes:
    i = p2p_did.index("-")
    return (serial[-7:] + p2p_did[i:i + 9]).encode()


def encrypt_p2p(data: bytes, key: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 (richiesto dal protocollo)
    return enc.update(data) + enc.finalize()


def build_command_header(seq: int, command_type: int) -> bytes:
    return P2P_DATA_HEADER + struct.pack(">H", seq) + MAGIC_WORD + struct.pack("<H", command_type)


def build_void_payload(channel: int = 255) -> bytes:
    return b"\x00\x00" + b"\x00\x00" + b"\x01\x00" + bytes([channel, 0x00]) + b"\x00\x00"


def build_string_type_payload(enc_type: int, key: bytes, command_type: int, value: str, channel: int = 0) -> bytes:
    encrypted = key is not None and len(key) == 16 and enc_type != 0
    data = padding_p2p(value.encode()) if encrypted else value.encode()
    header = struct.pack("<H", len(data))
    channel_buf = bytes([channel, enc_type if encrypted else 0])
    body = encrypt_p2p(data, key) if encrypted else data
    return header + b"\x00\x00" + b"\x01\x00" + channel_buf + b"\x00\x00" + body


def build_lookup_with_key(p2p_did: str, dsk_key: str, local_ip: str, local_port: int) -> bytes:
    did = p2p_did_to_buffer(p2p_did)
    port_buf = struct.pack("<H", local_port)
    ip_buf = bytes(int(x) for x in reversed(local_ip.split(".")))
    magic = bytes([0, 0, 0, 0, 0, 0, 0, 0, 2, 4, 0, 0])
    return did + b"\x00\x02" + port_buf + ip_buf + magic + dsk_key.encode() + b"\x00\x00\x00\x00"


def build_check_cam(p2p_did: str) -> bytes:
    return p2p_did_to_buffer(p2p_did) + b"\x00\x00\x00"


def decode_p2p_cloud_ips(data: str) -> list[tuple[str, int]]:
    encoded = data.split(":")[0]
    out = bytearray(len(encoded) // 2)
    for i in range(len(data) // 2):
        z = 0x39
        for j in range(i):
            z ^= out[j]
        x = ord(data[i * 2 + 1]) - ord("A")
        y = (ord(data[i * 2]) - ord("A")) * 0x10
        out[i] = (z ^ CLOUD_LOOKUP_TABLE[i % len(CLOUD_LOOKUP_TABLE)] ^ (x + y)) & 0xFF
    return [(ip, 32100) for ip in out.decode("utf-8", "ignore").split(",") if ip]


def build_privacy_json(admin_user_id: str, privacy_on: bool, channel: int = 0) -> str:
    return json.dumps({
        "account_id": admin_user_id, "cmd": CMD_PRIVACY,
        "mChannel": channel, "mValue3": 0,
        "payload": {"switch": 1 if privacy_on else 0},
    }, separators=(",", ":"))


# ── Sessione P2P ─────────────────────────────────────────────────────────────
class P2PError(Exception):
    pass


class P2PSession:
    def __init__(self, serial, p2p_did, dsk_key, admin_user_id, cloud_ips,
                 channel=0, timeout=2.0):
        self.serial = serial
        self.p2p_did = p2p_did
        self.dsk_key = dsk_key
        self.admin_user_id = admin_user_id
        self.cloud_ips = cloud_ips           # list[(host, port)]
        self.channel = channel
        self.key = derive_key(serial, p2p_did)
        self.addr = None                     # (ip, port) della camera
        self.seq = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(("0.0.0.0", 0))
        self.sock.settimeout(timeout)
        self._localport = self.sock.getsockname()[1]

    def _send(self, addr, msgid: bytes, payload: bytes = b""):
        self.sock.sendto(msgid + struct.pack(">H", len(payload)) + payload, addr)

    def _candidates_from_lookup(self) -> list[tuple[str, int]]:
        """Manda LOOKUP_WITH_KEY ai server cloud e raccoglie gli indirizzi camera."""
        local_ip = _local_ip()
        payload = build_lookup_with_key(self.p2p_did, self.dsk_key, local_ip, self._localport)
        for host, port in self.cloud_ips:
            self._send((host, port), LOOKUP_WITH_KEY, payload)
        found = []
        t_end = time.time() + 3
        while time.time() < t_end:
            try:
                msg, _ = self.sock.recvfrom(4096)
            except socket.timeout:
                break
            mid = msg[:2]
            if mid in (LOOKUP_ADDR, LOCAL_LOOKUP_RESP) and len(msg) >= 12:
                # LOOKUP_ADDR: porta a [6:8] LE, ip a [11],[10],[9],[8]
                port = struct.unpack("<H", msg[6:8])[0]
                ip = ".".join(str(b) for b in msg[11:7:-1])
                if port and (ip, port) not in found:
                    found.append((ip, port))
        return found

    def connect(self):
        candidates = self._candidates_from_lookup()
        if not candidates:
            raise P2PError("nessun indirizzo camera dal lookup")
        # CHECK_CAM verso ogni candidato e porte ±3, attesa CAM_ID
        checkcam = build_check_cam(self.p2p_did)
        for ip, port in candidates:
            for p in range(max(1, port - 3), port + 4):
                self._send((ip, p), CHECK_CAM, checkcam)
        t_end = time.time() + 4
        while time.time() < t_end:
            try:
                msg, src = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            if msg[:2] == CAM_ID:
                self.addr = src
                break
        if not self.addr:
            raise P2PError("nessun CAM_ID: camera non raggiungibile")
        self._gateway_info()
        return self

    def _gateway_info(self):
        """Handshake GATEWAYINFO: la lib lo usa per negoziare la chiave; noi la deriviamo,
        ma replichiamo lo scambio (consuma+ACK la risposta)."""
        self._send_data(CMD_GATEWAYINFO, build_void_payload(255))
        self._drain(1.5)

    def _send_data(self, command_type: int, framed_payload: bytes):
        pkt = build_command_header(self.seq, command_type) + framed_payload
        self._send(self.addr, DATA, pkt)
        self.seq += 1

    def _drain(self, secs: float):
        """Legge i pacchetti in arrivo per `secs`: risponde a PING e ACK ai DATA."""
        t_end = time.time() + secs
        while time.time() < t_end:
            try:
                msg, src = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            mid = msg[:2]
            if mid == PING:
                self._send(src, PONG, msg[4:] if len(msg) > 4 else b"")
            elif mid == DATA:
                # ACK del DATA in arrivo: dataType(2) + count(1 BE) + seqNo(2 BE)
                seq_no = struct.unpack(">H", msg[6:8])[0] if len(msg) >= 8 else 0
                self._send(src, ACK, P2P_DATA_HEADER + struct.pack(">H", 1) + struct.pack(">H", seq_no))

    def set_privacy(self, on: bool) -> bool:
        """Invia il comando privacy e attende l'ACK del nostro seq."""
        value = build_privacy_json(self.admin_user_id, on, self.channel)
        payload = build_string_type_payload(ENC_TYPE, self.key, CMD_SET_PAYLOAD, value, self.channel)
        my_seq = self.seq
        self._send_data(CMD_SET_PAYLOAD, payload)
        # attesa ACK del nostro seq (+ servizio PING/DATA)
        t_end = time.time() + 5
        while time.time() < t_end:
            try:
                msg, src = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            mid = msg[:2]
            if mid == ACK and _ack_contains(msg, my_seq):
                return True
            if mid == PING:
                self._send(src, PONG, msg[4:] if len(msg) > 4 else b"")
            elif mid == DATA:
                seq_no = struct.unpack(">H", msg[6:8])[0] if len(msg) >= 8 else 0
                self._send(src, ACK, P2P_DATA_HEADER + struct.pack(">H", 1) + struct.pack(">H", seq_no))
        return False

    def close(self):
        try:
            if self.addr:
                self._send(self.addr, END, b"")
        finally:
            self.sock.close()


def _ack_contains(msg: bytes, seq: int) -> bool:
    # ACK: msgid(2)+len(2) | dataType(2) numAcks(2 BE) seq...(2 BE each)
    body = msg[4:]
    if len(body) < 6:
        return False
    num = struct.unpack(">H", body[2:4])[0]
    for k in range(num):
        off = 4 + k * 2
        if off + 2 <= len(body) and struct.unpack(">H", body[off:off + 2])[0] == seq:
            return True
    return False


def _local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "0.0.0.0"
    finally:
        s.close()
