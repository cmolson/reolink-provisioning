#!/usr/bin/env python3
"""
Put a Reolink camera on a Wi-Fi network over Bluetooth LE.

For the models that won't scan a setup QR code and expect credentials over BLE
instead, like the E1 Pro. Protocol is written up in ../PROTOCOL.md.

Needs bleak and cryptography, see requirements.txt.

    # dry run, does the handshake and stops
    python reolink_ble_provision.py

    # actually set the Wi-Fi
    python reolink_ble_provision.py --provision --ssid MyWifi --password secret

    # pick a specific camera
    python reolink_ble_provision.py --provision --address AA:BB:CC:DD:EE:FF ...
"""
import argparse
import asyncio
import binascii
import hashlib
import json
import os
import struct
import sys

from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERVICE_UUID = "3d24bfff-0bcb-08bd-e5fc-0647025b2dce"
CHAR_UUID = "0000aaaa-0000-1000-8000-00805f9b34fb"

T_ENC_VERSION, T_RANDOM1, T_SERVER_PUB, T_RANDOM2, T_CLIENT_PUB, T_MTU = 1, 2, 3, 4, 5, 6
T_WIFI = 100001

ENCRYPT_VERSION = 1
PBKDF2_ITERATIONS = 10000
SCAN_TIMEOUT = 15.0
HANDSHAKE_TIMEOUT = 15.0
REPLY_TIMEOUT = 45.0


def le32(v: int) -> bytes:
    return struct.pack("<I", v)


def tlv(t: int, val: bytes) -> bytes:
    return le32(t) + le32(len(val)) + bytes(val)


def frame(payload: bytes) -> bytes:
    return le32(len(payload)) + payload


def parse_tlvs(buf: bytes):
    out, i = [], 0
    while i + 8 <= len(buf):
        t, ln = struct.unpack_from("<I", buf, i)[0], struct.unpack_from("<I", buf, i + 4)[0]
        if i + 8 + ln > len(buf):
            break
        out.append((t, buf[i + 8 : i + 8 + ln]))
        i += 8 + ln
    return out


def hx(b: bytes) -> str:
    return binascii.hexlify(bytes(b)).decode()


def derive_key_iv(random1: bytes, random2: bytes, shared: bytes):
    """Session key and IV. See TESTVECTORS.md if you're porting this."""
    okm = hashlib.pbkdf2_hmac("sha256", random1 + random2, shared,
                              PBKDF2_ITERATIONS, dklen=32)
    return okm[:16], okm[16:32]


class Reassembler:
    """Messages arrive as [uint32_le len][payload], split across notifications."""

    def __init__(self):
        self.buf = bytearray()
        self.need = 0
        self.queue: "asyncio.Queue[bytes]" = asyncio.Queue()

    def feed(self, data: bytes):
        self.buf.extend(data)
        while True:
            if self.need == 0:
                if len(self.buf) < 4:
                    return
                self.need = struct.unpack_from("<I", self.buf, 0)[0]
                del self.buf[:4]
            if len(self.buf) < self.need:
                return
            msg = bytes(self.buf[: self.need])
            del self.buf[: self.need]
            self.need = 0
            self.queue.put_nowait(msg)


async def find_camera(address: str | None):
    """
    Find a camera in setup mode.

    These advertise a name but not the service UUID, so filtering on the UUID
    finds nothing. Match the name, and check the service after connecting. The
    UUID check is kept in case other models do advertise it.
    """
    if address:
        return await BleakScanner.find_device_by_address(address, timeout=SCAN_TIMEOUT)
    devices = await BleakScanner.discover(timeout=SCAN_TIMEOUT, return_adv=True)
    for dev, adv in devices.values():
        name = (dev.name or adv.local_name or "").lower()
        uuids = [u.lower() for u in (adv.service_uuids or [])]
        if name.startswith("reolink") or SERVICE_UUID in uuids:
            return dev
    return None


async def provision(address, ssid, password, country, do_provision):
    dev = await find_camera(address)
    if not dev:
        print("No Reolink camera advertising. Is it in setup mode?")
        return False
    print(f"Found {dev.name} [{dev.address}]")

    rx = Reassembler()
    async with BleakClient(dev, timeout=30.0) as client:
        # service discovery can lag the connection
        char = None
        for _ in range(10):
            char = client.services.get_characteristic(CHAR_UUID)
            if char:
                break
            await asyncio.sleep(0.5)
        if not char:
            print("Vendor characteristic not found")
            return False
        mtu = client.mtu_size or 23
        print(f"Connected, mtu={mtu}")
        await client.start_notify(char, lambda _h, d: rx.feed(bytes(d)))

        async def send(payload: bytes):
            await client.write_gatt_char(char, frame(payload), response=True)

        await send(tlv(T_ENC_VERSION, le32(ENCRYPT_VERSION)) + tlv(T_MTU, le32(mtu)))

        device_random1 = server_pub = None
        try:
            while server_pub is None:
                msg = await asyncio.wait_for(rx.queue.get(), timeout=HANDSHAKE_TIMEOUT)
                for t, v in parse_tlvs(msg):
                    if t == T_RANDOM1:
                        device_random1 = v
                    elif t == T_SERVER_PUB:
                        server_pub = v
        except asyncio.TimeoutError:
            print("Camera didn't answer the handshake. Check nothing else is "
                  "connected to it, these only take one client at a time.")
            return False
        if device_random1 is None:
            print("Camera sent a public key but no random, can't derive a key.")
            return False

        priv = ec.generate_private_key(ec.SECP256R1())
        app_pub = priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        app_random2 = os.urandom(64)
        await send(tlv(T_RANDOM2, app_random2) + tlv(T_CLIENT_PUB, app_pub))

        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_pub)
        shared = priv.exchange(ec.ECDH(), peer)
        aes_key, aes_iv = derive_key_iv(device_random1, app_random2, shared)
        print(f"Handshake done, key={hx(aes_key)} iv={hx(aes_iv)}")

        if not do_provision:
            print("Dry run, nothing sent.")
            return True

        # cmd 4 is test-and-set
        body = json.dumps(
            {"cmd": 4, "id": 1, "data": {"s": ssid, "p": password, "c": country}},
            separators=(",", ":"),
        ).encode()
        enc = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv)).encryptor()
        await send(enc.update(tlv(T_WIFI, body)) + enc.finalize())
        print(f"Sent Wi-Fi config for ssid={ssid!r} country={country}")

        # A camera that joins can tear down its BLE stack before replying, so a
        # timeout here doesn't mean it failed.
        try:
            reply = await asyncio.wait_for(rx.queue.get(), timeout=REPLY_TIMEOUT)
        except asyncio.TimeoutError:
            print(f"No reply after {REPLY_TIMEOUT:.0f}s. It may have joined anyway, "
                  "check the client list on your AP.")
            return False
        dec = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv)).decryptor()
        pt = dec.update(reply) + dec.finalize()
        ok = False
        for t, v in parse_tlvs(pt):
            if t != T_WIFI:
                continue
            print(f"Reply: {v.decode(errors='replace')}")
            try:
                data = json.loads(v).get("data", {})
            except ValueError:
                print("That didn't parse as JSON, so the session key is probably wrong.")
                continue
            ok = data.get("code") == 0 and data.get("result") == 0
        print("Done" if ok else "Camera didn't report success")
        return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provision", action="store_true",
                    help="actually set Wi-Fi (default is a handshake-only dry run)")
    ap.add_argument("--address", help="target a specific camera by BLE address")
    ap.add_argument("--ssid")
    ap.add_argument("--password")
    ap.add_argument("--country", default="US")
    a = ap.parse_args()
    if a.provision and not (a.ssid and a.password):
        ap.error("--provision requires --ssid and --password")
    ok = asyncio.run(provision(a.address, a.ssid, a.password, a.country, a.provision))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
