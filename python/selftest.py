#!/usr/bin/env python3
"""
Check the crypto against the vectors in ../TESTVECTORS.md. No camera needed.

    python selftest.py
"""
import binascii
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from reolink_ble_provision import derive_key_iv, frame, parse_tlvs, tlv

unhex = binascii.unhexlify
hx = lambda b: binascii.hexlify(b).decode()

CLIENT_PRIV = 0x1111111111111111111111111111111111111111111111111111111111111111
CAMERA_PRIV = 0x2222222222222222222222222222222222222222222222222222222222222222
RANDOM1 = bytes(range(64))
RANDOM2 = bytes((0xFF - i) & 0xFF for i in range(64))

EXPECT_SHARED = "ccfc261f58193c98ca4ad4a53bbac6f0ee29bc4d48438090446908622ca79af6"
EXPECT_KEY = "68e554ef38cfc21accf5bf4e1a9dbd9b"
EXPECT_IV = "d68cf656689b3ea2845d003ed2da9a97"
EXPECT_FRAME = (
    "4a0000000ab7d1ff30f3f366f1d73f7e39f91199078512512efea5a1b6e71e9d5381ff851f20f2ba"
    "243cbb0231817093aae4fbd8645b23e83ea52aaf282b1ea8d423d5839b334c43f0929c58a919"
)

failures = []


def check(name, got, want):
    if got == want:
        print(f"ok    {name}")
    else:
        print(f"FAIL  {name}\n        got  {got}\n        want {want}")
        failures.append(name)


def main():
    client = ec.derive_private_key(CLIENT_PRIV, ec.SECP256R1())
    camera = ec.derive_private_key(CAMERA_PRIV, ec.SECP256R1())

    shared = client.exchange(ec.ECDH(), camera.public_key())
    check("ecdh shared secret", hx(shared), EXPECT_SHARED)

    # both ends must land on the same secret
    check("ecdh is symmetric", hx(camera.exchange(ec.ECDH(), client.public_key())), EXPECT_SHARED)

    key, iv = derive_key_iv(RANDOM1, RANDOM2, shared)
    check("aes key", hx(key), EXPECT_KEY)
    check("aes iv", hx(iv), EXPECT_IV)

    body = b'{"cmd":4,"id":1,"data":{"s":"TestNetwork","p":"hunter2","c":"CA"}}'
    enc = Cipher(algorithms.AES(key), modes.CFB(iv)).encryptor()
    built = frame(enc.update(tlv(100001, body)) + enc.finalize())
    check("encrypted cmd 4 frame", hx(built), EXPECT_FRAME)

    # and it decrypts back to the same TLV
    cipher = unhex(EXPECT_FRAME)[4:]
    dec = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
    tlvs = parse_tlvs(dec.update(cipher) + dec.finalize())
    check("round trip", (tlvs[0][0], tlvs[0][1]), (100001, body))

    print()
    if failures:
        print(f"{len(failures)} failed")
        return 1
    print("all good")
    return 0


if __name__ == "__main__":
    sys.exit(main())
