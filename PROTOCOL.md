# Reolink BLE Wi-Fi provisioning protocol

How the Reolink app hands Wi-Fi credentials to a camera over Bluetooth LE, for
the models that are set up that way instead of by scanning a QR code (the E1 Pro
/ E330 revision with a Bluetooth stack, for one).

This came out of Reolink's published firmware images and their Android app, and
it's been checked against a real camera. Nothing below is a guess.

## GATT

| | |
|---|---|
| Service | `3d24bfff-0bcb-08bd-e5fc-0647025b2dce` |
| Characteristic | `0000aaaa-0000-1000-8000-00805f9b34fb` (write + notify, read isn't supported) |

A camera in setup mode advertises as `Reolink_<uid>`, where the uid isn't derived
from the MAC.

Watch out for this one: the advertisement carries the name but not the service
UUID. On hardware the advertised service UUID list comes back empty, so a scan
filtered on the service UUID never matches anything. Filter on the `Reolink` name
prefix instead, or connect to a known address, and check for the service once
you're connected.

## Framing

Every write to the characteristic is `[uint32_le total_len][payload]`.

Notifications coming back are reassembled the same way. Read the first 4 bytes as
a little-endian length, then collect that many bytes across however many
notifications it takes, since one message usually spans several packets.

The payload is one or more TLVs, little-endian throughout:

```
TLV = [uint32_le type][uint32_le len][value]
```

## Handshake

Plaintext, since there's no key yet. These TLV types only show up here:

| type | name | direction | value |
|---|---|---|---|
| 1 | ENCRYPT_VERSION | client to camera | `le32(1)` |
| 6 | MTU | client to camera | `le32(mtu)` |
| 2 | RANDOM1 | camera to client | 64 random bytes |
| 3 | SERVER_PUBLIC_KEY | camera to client | 65-byte P-256 point, `04 || X || Y` |
| 4 | RANDOM2 | client to camera | 64 random bytes |
| 5 | CLIENT_PUBLIC_KEY | client to camera | 65-byte P-256 point, `04 || X || Y` |

In order:

1. client sends `TLV(1, le32(1))` and `TLV(6, le32(mtu))`
2. camera sends `TLV(2, random1[64])` and `TLV(3, serverPub[65])`
3. client sends `TLV(4, random2[64])` and `TLV(5, clientPub[65])`

The camera also echoes `TLV(1, le32(1))` back as a version ack.

## Key derivation

```
shared = ECDH_secp256r1(clientPrivate, cameraPublic)          # 32 bytes
okm    = PBKDF2-HMAC-SHA256(
             password   = random1 || random2,                 # 128 bytes
             salt       = shared,                             # 32 bytes
             iterations = 10000,
             dkLen      = 32)
aesKey = okm[0:16]
aesIv  = okm[16:32]
```

Cipher is AES-128-CFB, i.e. `AES/CFB/NoPadding` with 128-bit feedback.

The password and salt are the way round you'd not expect: the password is the two
randoms glued together, and the salt is the ECDH shared secret.

## Wi-Fi command

TLV type `100001` carries the encrypted config.

```
json = {"cmd":4,"id":<n>,"data":{"s":ssid,"p":password,"c":country}}
inner = TLV(100001, utf8(json))
ciphertext = AES_CFB_encrypt(inner, aesKey, aesIv)
write [uint32_le len(ciphertext)][ciphertext]
```

`cmd` values:

| cmd | meaning |
|---|---|
| 1 | AP scan |
| 2 | Wi-Fi test |
| 3 | Wi-Fi set |
| 4 | Wi-Fi test-and-set. Tries the credentials, saves them if they work. This is the one you want. |
| 5 | report capabilities, then tear down the BLE stack |

`data` fields are `s` for SSID (max 127), `p` for password (max 127) and `c` for
country code (max 31).

The reply comes back encrypted the same way. Decrypt it and parse the TLV:

```
TLV(100001, {"data":{"code":0,"result":0},"id":<n>,"rep":4})
```

`code` and `result` both zero means the camera took the config, and for cmd 4
that it's joined the network.

Don't rely on getting a reply at all though. A camera that joins successfully may
tear down its Bluetooth stack before it answers, which looks identical to a
timeout. The client list on your AP is the thing to trust.

## If you're implementing this

Two things cost me time, neither of them in the protocol itself:

**The advertisement has no service UUID.** Covered above, but worth repeating
because it fails silently: filter your scan on the name, not the UUID.

**Don't trust callback ordering.** On an Android/Qualcomm stack the MTU gets
negotiated by the stack on connect, so `onMtuChanged` arrives *before*
`onServicesDiscovered`. Code that enables notifications from the MTU callback
looks up a service that doesn't exist yet, gets null, and drops a connection that
was perfectly healthy. Wait until services are actually discovered. The same code
was fine on BlueZ, which is exactly why it went unnoticed for a while.

Connecting straight out of a scan callback also tends to fail (status 133 on
Android). Stop the scan, pause briefly, then connect.

## Odds and ends

There's no cloud token anywhere in the Wi-Fi path. The ECDH handshake is
unauthenticated, so none of this needs a Reolink account.

The 16-character UID printed on the camera body identifies the device, it isn't a
provisioning secret, and it plays no part in this exchange.

The same service UUID, characteristic and command set turn up across different
Reolink SoCs, so one implementation should cover most of their BLE models.
