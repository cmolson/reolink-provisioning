# Kotlin

Split in two so the reusable half doesn't drag in Android.

`jvm/ReolinkBleCrypto.kt` is the crypto and framing: ECDH secp256r1,
PBKDF2-HMAC-SHA256, AES-128-CFB, and the TLV build/parse. Plain JVM, only
`java.security` and `javax.crypto`, so it builds and unit tests anywhere.

`android/ReolinkBleProvisioner.kt` is a BluetoothGatt client on top of that. It
does the handshake and sends the encrypted Wi-Fi command. Hand it a Context:

```kotlin
val ok = ReolinkBleProvisioner(context)
    .provisionFirstAvailable(ssid = "MyWifi", password = "secret", country = "CA")
```

It needs `BLUETOOTH_SCAN` and `BLUETOOTH_CONNECT` on API 31+, or `BLUETOOTH`,
`BLUETOOTH_ADMIN` and `ACCESS_FINE_LOCATION` on older ones, with Bluetooth
switched on. The camera has to be in setup mode and advertising.

Two things that bit me getting this working on a real Android device, both
handled in the code but worth knowing if you write your own:

* Some stacks negotiate the MTU themselves on connect, so `onMtuChanged` can
  arrive *before* service discovery has finished. Don't hang your setup off that
  callback without checking the service is actually there, or you'll look up a
  null service and give up on a connection that was fine.
* Connecting straight out of a scan callback tends to fail (the usual status
  133). Stop the scan and give it a moment first.

Both are in the package `dev.cmolabs.reolinkble`. There's no Gradle build here,
just the sources, so drop them wherever they fit: the JVM one in a plain Kotlin
module and the Android one in an Android module that depends on it.

## Android version note

This was written against API 31/32, so it uses the older BluetoothGatt calls:
`characteristic.value`, `writeCharacteristic(characteristic)`, and the two
argument `onCharacteristicChanged`. They still work higher up, but they're
deprecated from API 33, where the framework hands you the bytes directly.

If you're compiling against 33 or later, override the three argument
`onCharacteristicChanged(gatt, characteristic, value)` and read `value` from the
parameter rather than off the characteristic, and use
`writeCharacteristic(characteristic, value, writeType)`. Don't just swap them in
blind on an older compileSdk though, those overloads won't exist.

Wire format is in [../PROTOCOL.md](../PROTOCOL.md).
