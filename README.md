# reolink-provisioning

Get a Reolink camera onto your Wi-Fi without the Reolink app and without a cloud
account.

There are two ways these cameras take credentials. Most of them scan a QR code
off your screen with their own lens. Some won't: the E1 Pro (the E330 revision
with a Bluetooth stack) ignores the QR entirely and expects the app to hand it
credentials over Bluetooth LE instead. If you don't want to use the app, that
second group leaves you stuck.

So I pulled the BLE protocol out of Reolink's published firmware, checked it
against their Android app, and wrote a client. It works: the camera takes the
credentials and joins the network. Both methods are covered here.

[PROTOCOL.md](PROTOCOL.md) has the BLE protocol written up, and
[TESTVECTORS.md](TESTVECTORS.md) has fixed inputs and expected outputs if you're
porting it.

## What's here

* `python/reolink_ble_provision.py` - the BLE client.
* `python/reolink_qr.py` - generates the setup QR for the cameras that scan one.
* `python/selftest.py` - checks the crypto against the test vectors, no camera
  needed.
* `kotlin/jvm/` - the crypto and framing as a plain JVM library, no Android
  dependency, so you can unit test it anywhere.
* `kotlin/android/` - a BluetoothGatt client built on that, for embedding in an
  Android app.

## Bluetooth

```bash
cd python
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

Factory-reset the camera first so it goes back into setup mode. You'll know it's
ready when it starts asking you to open the Reolink app, that's the state where
it advertises over BLE.

```bash
# dry run: connect, do the handshake, derive the key, send nothing
python reolink_ble_provision.py

# the real thing
python reolink_ble_provision.py --provision --ssid MyWifi --password secret --country CA
```

It picks the first camera advertising a Reolink name. Use `--address` if you have
several and want a specific one.

It sends the test-and-set command, so the camera tries the credentials before it
saves them. Get the password wrong and the test just fails, rather than leaving
the camera half configured.

One thing worth knowing: sometimes the camera joins the network and tears down
its Bluetooth stack without bothering to reply, so you get a timeout even though
it worked. Check your router's client list before assuming it failed.

## QR

For the models that do scan a code:

```bash
python reolink_qr.py --ssid MyWifi --password secret          # prints to terminal
python reolink_qr.py --ssid MyWifi --password secret --png setup.png
```

Hold it up to the camera while it's in setup mode.

## Getting video out of it afterwards

Worth knowing before you wonder why your camera is on the network but useless: a
factory-fresh Reolink has every service port shut except the Baichuan one on
9000. RTSP (554), HTTP (80) and ONVIF (8000) are all disabled. Provisioning puts
the camera on your wifi, it does not turn any of that on, so the camera sits
there answering nothing.

Enabling them is a separate job and this repo doesn't do it. What worked for me
was [TinKurbatoff/reolink-init](https://github.com/TinKurbatoff/reolink-init):

```bash
python baichuan_init.py --port 9000 -p '' <camera-ip> probe
python baichuan_init.py --port 9000 -p '' <camera-ip> enable --ports http rtsp onvif
```

No admin password needed, the blank factory one works. The enabled ports survive
a reboot, but a factory reset turns them off again, so if you're resetting the
camera repeatedly while testing you'll be redoing this each time.

## Working out which camera is which

If you're matching a camera you already know against one sitting in setup mode,
the name it advertises is a hash of its UID:

```
Reolink_ + base64(sha256(uid))[:16]
```

You can't go backwards, but you don't need to — hash the UID you've got and
compare. Once a camera is on the network and port 80 is on, its UID comes from:

```bash
curl -s -X POST 'http://<ip>/cgi-bin/api.cgi?cmd=GetP2p&user=admin&password=' \
  -H 'Content-Type: application/json' -d '[{"cmd":"GetP2p","action":0,"param":{}}]'
```

Don't match on the MAC you saw over Bluetooth, by the way: the camera joins wifi
on a different one, a single octet off. Details and the exact numbers are in
[PROTOCOL.md](PROTOCOL.md#identifiers).

## Does it actually work

Yes. Tested against a Reolink E1 Pro: handshake, key exchange, credentials, and
the camera shows up on the network with a DHCP lease. With the ports enabled as
above it then serves RTSP normally (2880x1616 h264 in my case) and streams.

It's been run from two unrelated Bluetooth stacks, BlueZ on a laptop and Android
on a Qualcomm device, so the protocol itself doesn't appear to depend on either.

`python selftest.py` checks the crypto without needing hardware, and CI runs it
on every push.

## Legal

This is an independent implementation written for interoperability. The protocol
came from firmware images Reolink hosts publicly with nothing to click through,
and from looking at their Android app. There's no Reolink code in here, and no
keys or secrets, because the protocol doesn't have any. The handshake is a plain
unauthenticated ECDH exchange and the session key is derived fresh each time.

Use it on cameras you own. Reverse engineering for interoperability is carved out
in the EU Software Directive and US DMCA 1201(f), but neither is automatic, so get
your own advice if you're building a product on this.

Not affiliated with Reolink.
