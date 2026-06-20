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

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
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

# Comandi livestream (per lo snapshot fresco via P2P — Spike B)
CMD_DOORBELL_SET_PAYLOAD = 1700     # wrapper string-payload usato dalle solo-cam (C200/C210)
COMMAND_START_LIVESTREAM = 1000     # commandType nested dentro il payload 1700
CMD_STOP_REALTIME_MEDIA = 1004      # stop livestream (sendCommandWithInt)

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


# ── Livestream/snapshot: RSA + AES video + parsing frame (port di p2p/*.js) ───
# Flusso (station.js/session.js): start = CMD_DOORBELL_SET_PAYLOAD(1700) con JSON nested
# {commandType:1000, data:{accountId, encryptkey=<N pubblico hex>, streamtype}}. Il video
# arriva come CMD_VIDEO_FRAME: header (20B) + chiave AES RSA-cifrata (128B a [22:150] se
# signCode>0) + payload con i primi 128B in AES-128-ECB e il resto in chiaro. Stop = 1004.

def generate_rsa_keypair():
    """Coppia RSA-1024 per la sessione livestream. Ritorna (private_key, encryptkey_hex)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    return priv, rsa_public_modulus_hex(priv)


def rsa_public_modulus_hex(private_key) -> str:
    """Modulo N (128 byte) in hex, come `encryptkey` on-wire (node-rsa: .n.subarray(1))."""
    n = private_key.public_key().public_numbers().n
    return n.to_bytes(128, "big").hex()


def rsa_decrypt_aes_key(private_key, blob: bytes) -> bytes:
    """Decifra (RSA PKCS1 v1.5) la chiave AES per-frame inviata dalla cam."""
    return private_key.decrypt(blob, asym_padding.PKCS1v15())


def decrypt_video_chunk(aes_key: bytes, data: bytes) -> bytes:
    """AES-128-ECB NoPadding sui primi byte (cifrati) del payload video. len(data) %16==0."""
    dec = Cipher(algorithms.AES(aes_key), modes.ECB()).decryptor()  # noqa: S305 (protocollo)
    return dec.update(data) + dec.finalize()


def build_livestream_start_json(admin_user_id: str, encryptkey_hex: str, streamtype: int = 1) -> str:
    """Payload nested per avviare il livestream (streamtype 1=H.264, 2=H.265)."""
    return json.dumps({
        "commandType": COMMAND_START_LIVESTREAM,
        "data": {"accountId": admin_user_id, "encryptkey": encryptkey_hex, "streamtype": streamtype},
    }, separators=(",", ":"))


def find_start_code(data: bytes) -> bool:
    """True se `data` inizia con uno start-code H.264 (00 00 01 oppure 00 00 00 01)."""
    if not data:
        return False
    if len(data) >= 4:
        s = data[:4]
        if (s[0] == 0 and s[1] == 0 and s[2] == 1) or (s[0] == 0 and s[1] == 0 and s[2] == 0 and s[3] == 1):
            return True
    elif len(data) == 3:
        s = data[:3]
        if s[0] == 0 and s[1] == 0 and s[2] == 1:
            return True
    return False


def is_iframe(data: bytes) -> bool:
    """True se il NAL (offset 3 o 4 dopo lo start-code) e' un tipo I-frame/SPS/PPS."""
    valid = (64, 66, 68, 78, 101, 103)
    if data and len(data) >= 5:
        s = data[:5]
        return s[3] in valid or s[4] in valid
    return False


def parse_video_frame_header(data: bytes) -> dict:
    """Estrae i metadati dall'header (20 byte) di un CMD_VIDEO_FRAME."""
    return {
        "video_data_length": struct.unpack_from("<I", data, 0)[0],
        "is_key_frame": data[4] == 1,
        "stream_type": data[5],
        "video_seq_no": struct.unpack_from("<H", data, 6)[0],
        "video_fps": struct.unpack_from("<H", data, 8)[0],
        "video_width": struct.unpack_from("<H", data, 10)[0],
        "video_height": struct.unpack_from("<H", data, 12)[0],
        "video_timestamp": int.from_bytes(data[14:20], "little"),
    }


def extract_video_frame(data: bytes, sign_code: int, private_key) -> tuple[dict, bytes]:
    """Da un CMD_VIDEO_FRAME (bytes `data`) ricava (metadati, video_data decifrato).

    Se signCode>0 e videoDataLength>=128: la chiave AES e' a [22:150] RSA-cifrata, payload da 151,
    primi 128 byte AES-ECB + resto in chiaro. Altrimenti payload da 22, tutto in chiaro.
    """
    meta = parse_video_frame_header(data)
    vdl = meta["video_data_length"]
    payload_start = 22
    aes_key = None
    if sign_code > 0 and vdl >= 128:
        if private_key is None:
            raise P2PError("chiave RSA privata mancante: stream non decifrabile")
        aes_key = rsa_decrypt_aes_key(private_key, data[22:150])
        payload_start = 151
    if aes_key is not None:
        encrypted = data[payload_start:payload_start + 128]
        plain = data[payload_start + 128:payload_start + vdl]
        video = decrypt_video_chunk(aes_key, encrypted) + bytes(plain)
    else:
        video = bytes(data[payload_start:payload_start + vdl])
    return meta, video


# ── Framing pacchetti DATA in ricezione (per il video) ───────────────────────
# UDP DATA: f1d0 | bytesToRead(BE16) | dataTypeMarker(0xD1+type) | seqNo(BE16) | partData
# Messaggio riassemblato (prima parte): XZYH | cmdId(LE16) | bytesToRead(LE32) | resv(2) |
#   channel(1) | signCode(1) | type(1) | resv(1) = header 16B, poi il payload (message.data).
P2P_DATATYPE_DATA = 0
P2P_DATATYPE_VIDEO = 1
P2P_DATATYPE_CONTROL = 2
P2P_DATATYPE_BINARY = 3
P2P_DATA_HEADER_BYTES = 16
CMD_VIDEO_FRAME = 1300


def datatype_marker(data_type: int) -> bytes:
    return bytes([0xD1, data_type])


def parse_udp_data_packet(msg: bytes) -> "dict | None":
    """Scompone un pacchetto UDP DATA (msgid f1d0). None se non e' un DATA valido."""
    if len(msg) < 8 or msg[:2] != DATA:
        return None
    return {
        "bytes_to_read": struct.unpack(">H", msg[2:4])[0],
        "data_type": msg[5] if msg[4] == 0xD1 else -1,
        "seq_no": struct.unpack(">H", msg[6:8])[0],
        "part_data": msg[8:],
    }


def parse_message_header(assembled: bytes) -> dict:
    """Header (16B) di un messaggio riassemblato che inizia con XZYH."""
    return {
        "magic_ok": assembled[0:4] == MAGIC_WORD,
        "command_id": struct.unpack_from("<H", assembled, 4)[0],
        "bytes_to_read": struct.unpack_from("<I", assembled, 6)[0],
        "channel": assembled[12],
        "sign_code": assembled[13],
        "type": assembled[14],
    }


def build_ack_payload(data_type: int, seq_no: int) -> bytes:
    """Payload di un ACK per il dataType indicato (numAcks=1)."""
    return datatype_marker(data_type) + struct.pack(">H", 1) + struct.pack(">H", seq_no)


class VideoFrameAssembler:
    """Riassembla i pacchetti VIDEO (in ordine di seq) in frame CMD_VIDEO_FRAME completi.

    Semplificato per il caso snapshot: assume parti in ordine. `feed(part)` ritorna una lista
    di (header, frame_payload) completati. NB: il riassemblaggio multi-pacchetto e l'ordinamento
    sono il punto da validare LIVE (qui best-effort, parti assunte in ordine di arrivo).
    """

    def __init__(self):
        self._buf = b""
        self._header = None

    def feed(self, part_data: bytes) -> list:
        self._buf += part_data
        out = []
        while True:
            if self._header is None:
                if len(self._buf) < P2P_DATA_HEADER_BYTES or self._buf[0:4] != MAGIC_WORD:
                    break
                self._header = parse_message_header(self._buf)
                self._buf = self._buf[P2P_DATA_HEADER_BYTES:]
            need = self._header["bytes_to_read"]
            if len(self._buf) < need:
                break
            out.append((self._header, self._buf[:need]))
            self._buf = self._buf[need:]
            self._header = None
        return out


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

    # ── Livestream / snapshot keyframe ───────────────────────────────────────
    # NB: il flusso video (start → ricezione/decrypt → I-frame) e' portato fedelmente dalla
    # lib JS ma il loop socket e il riassemblaggio multi-pacchetto vanno VALIDATI LIVE su una
    # cam reale. `dump_path` salva i pacchetti UDP grezzi per il debug offline se qualcosa non torna.

    def start_livestream(self, encryptkey: str, streamtype: int = 1):
        """Avvia il livestream (CMD_DOORBELL_SET_PAYLOAD 1700 con payload nested 1000)."""
        value = build_livestream_start_json(self.admin_user_id, encryptkey, streamtype)
        payload = build_string_type_payload(ENC_TYPE, self.key, CMD_DOORBELL_SET_PAYLOAD, value, self.channel)
        self._send_data(CMD_DOORBELL_SET_PAYLOAD, payload)

    def stop_livestream(self):
        """Stop best-effort del livestream (CMD_STOP_REALTIME_MEDIA 1004)."""
        payload = build_string_type_payload(0, b"", CMD_STOP_REALTIME_MEDIA, str(self.channel), self.channel)
        self._send_data(CMD_STOP_REALTIME_MEDIA, payload)

    def grab_keyframe(self, rsa_private_key, encryptkey: str, timeout: float = 15.0, dump_path=None) -> bytes:
        """Avvia lo stream e accumula H.264 fino al primo keyframe completo. Ritorna il bitstream.

        Rileva l'IDR via flag is_key_frame nell'header del frame; considera l'IDR "completo"
        quando arriva un frame successivo (boundary). Ritorna l'Annex-B accumulato (SPS+PPS+IDR+...).
        """
        self.start_livestream(encryptkey)
        assembler = VideoFrameAssembler()
        h264 = bytearray()
        got_keyframe = False
        complete = False
        dump = open(dump_path, "wb") if dump_path else None
        t_end = time.time() + timeout
        try:
            while time.time() < t_end and not complete:
                try:
                    msg, src = self.sock.recvfrom(16384)
                except socket.timeout:
                    continue
                if dump:
                    dump.write(struct.pack(">I", len(msg)) + msg)
                mid = msg[:2]
                if mid == PING:
                    self._send(src, PONG, msg[4:] if len(msg) > 4 else b"")
                    continue
                if mid != DATA:
                    continue
                pkt = parse_udp_data_packet(msg)
                if pkt is None:
                    continue
                self._send(src, ACK, build_ack_payload(pkt["data_type"], pkt["seq_no"]))
                if pkt["data_type"] != P2P_DATATYPE_VIDEO:
                    continue
                for header, frame_payload in assembler.feed(pkt["part_data"]):
                    if header["command_id"] != CMD_VIDEO_FRAME:
                        continue
                    try:
                        meta, video = extract_video_frame(frame_payload, header["sign_code"], rsa_private_key)
                    except Exception:  # noqa: BLE001 — pacchetto corrotto/chiave: salta il frame
                        continue
                    h264.extend(video)
                    if meta["is_key_frame"]:
                        got_keyframe = True
                    elif got_keyframe:
                        complete = True  # un frame dopo il keyframe => IDR completo
                        break
        finally:
            if dump:
                dump.close()
        if not h264:
            raise P2PError("nessun dato video ricevuto (start livestream non confermato?)")
        if not got_keyframe:
            raise P2PError("nessun keyframe ricevuto entro il timeout")
        return bytes(h264)

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
