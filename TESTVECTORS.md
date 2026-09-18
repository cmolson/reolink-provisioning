# Test vectors

Fixed inputs and the values they should produce, so you can check a port without
having a camera to hand. `python/selftest.py` runs these.

Real sessions use random keys and randoms, obviously. The fixed private keys here
are just so the numbers come out the same every time.

## Inputs

```
client private scalar  1111111111111111111111111111111111111111111111111111111111111111
camera private scalar   2222222222222222222222222222222222222222222222222222222222222222
                        (both secp256r1, big-endian)

random1 (camera)        000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                        202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f

random2 (client)        fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0
                        dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0
```

Public keys, as they go on the wire (65 bytes, `04 || X || Y`):

```
client  040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed
        194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794

camera  04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf
        350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285
```

## Derived

```
ecdh shared    ccfc261f58193c98ca4ad4a53bbac6f0ee29bc4d48438090446908622ca79af6

pbkdf2 out     68e554ef38cfc21accf5bf4e1a9dbd9bd68cf656689b3ea2845d003ed2da9a97
  (password = random1 || random2, salt = shared, 10000 iterations, 32 bytes)

aes key        68e554ef38cfc21accf5bf4e1a9dbd9b      (out[0:16])
aes iv         d68cf656689b3ea2845d003ed2da9a97      (out[16:32])
```

## A full Wi-Fi command

Plaintext JSON:

```json
{"cmd":4,"id":1,"data":{"s":"TestNetwork","p":"hunter2","c":"CA"}}
```

Wrapped as `TLV(100001, json)`, encrypted AES-128-CFB with the key and IV above,
then length-prefixed. The bytes that go out on the characteristic:

```
4a0000000ab7d1ff30f3f366f1d73f7e39f91199078512512efea5a1b6e71e9d5381ff851f20f2ba
243cbb0231817093aae4fbd8645b23e83ea52aaf282b1ea8d423d5839b334c43f0929c58a919
```

The leading `4a000000` is the little-endian length (74) of what follows.

## QR payload

For the camera models that scan a code instead:

```
build("MyWifi", "secret", "ABCD1234")  ->  <QR><S>MyWifi</S><P>secret</P><C>1234</C></QR>
build("MyWifi", "secret")              ->  <QR><S>MyWifi</S><P>secret</P></QR>
```
