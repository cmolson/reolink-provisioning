#!/usr/bin/env python3
"""
Make the setup QR code that Reolink cameras scan with their own lens.

This is the other way Reolink cameras get onto Wi-Fi, used by the models that
do have a working QR path. You show this code to the camera while it's in setup
mode and it reads the credentials straight off the screen. Cameras like the E1
Pro ignore it and want BLE instead, which is what the rest of this repo is for.

Payload is plain text:

    <QR><S>ssid</S><P>password</P><C>####</C></QR>

where #### is the last four characters of the camera serial. The <C> field looks
to be optional, pass --serial if you want to include it.

Needs the qrcode package.

    python reolink_qr.py --ssid MyWifi --password secret
    python reolink_qr.py --ssid MyWifi --password secret --png setup.png
"""
import argparse
import sys

SSID_MAX = 31
PASSWORD_MAX = 64


def build(ssid: str, password: str, camera_serial: str | None = None) -> str:
    # The payload is XML-ish with no escaping, so these characters break it.
    for label, value in (("ssid", ssid), ("password", password)):
        bad = [c for c in "<>&" if c in value]
        if bad:
            sys.exit(f"{label} contains {bad}, which this payload can't escape")
    if len(ssid) > SSID_MAX:
        sys.exit(f"ssid is {len(ssid)} chars, limit is {SSID_MAX}")
    if len(password) > PASSWORD_MAX:
        sys.exit(f"password is {len(password)} chars, limit is {PASSWORD_MAX}")
    tail = f"<C>{camera_serial[-4:]}</C>" if camera_serial else ""
    return f"<QR><S>{ssid}</S><P>{password}</P>{tail}</QR>"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ssid", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--serial", help="camera serial, last 4 go in the <C> field")
    p.add_argument("--png", help="also write a PNG here")
    p.add_argument("--scale", type=int, default=10, help="PNG box size, default 10")
    a = p.parse_args()

    payload = build(a.ssid, a.password, a.serial)
    print(f"payload: {payload}\n")

    import qrcode

    # Low error correction and a decent border: the camera wants a big clean
    # target more than it wants redundancy.
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=a.scale,
        border=4,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    qr.print_ascii(invert=True)

    if a.png:
        qr.make_image(fill_color="black", back_color="white").save(a.png)
        print(f"wrote {a.png}")


if __name__ == "__main__":
    main()
