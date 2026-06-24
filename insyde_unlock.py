#!/usr/bin/env python3
"""
Master Password Generator for InsydeH2O BIOS  (Acer / HP / Compal / Fujitsu-Siemens)
For the "System Disabled" / unlock hash shown after 3 invalid password attempts.

Algorithm: dogbert <dogber1@gmail.com>, GPLv2  (ported to Python 3).
Use only on hardware you own / are authorized to service.

Usage:
    python insyde_unlock.py 03133610      # pass the hash as an argument
    python insyde_unlock.py               # or run with no args and type it in

Notes:
  * Enter three wrong passwords; the BIOS shows an 8-digit hash (e.g. 03133610
    or 0313-3610). Hyphens are ignored.
  * The generated master password is encoded for a US QWERTY layout -- type it
    on that layout.
  * The hash often changes on each lockout, so generate from a FRESH code and
    don't reboot between reading the code and typing the result.
"""

import sys


def calc_password(str_hash: str) -> str:
    salt = "Iou|hj&Z"
    pwd = ""
    for i in range(8):
        b = ord(salt[i]) ^ ord(str_hash[i])
        a = b
        a = (a * 0x66666667) >> 32
        a = (a >> 2) | (a & 0xC0)
        if a & 0x80000000:
            a += 1
        a *= 10
        pwd += str(b - a)   # == (salt[i] ^ hash[i]) mod 10
    return pwd


def main() -> int:
    if len(sys.argv) > 1:
        in_hash = sys.argv[1]
    else:
        print("Master Password Generator for InsydeH2O BIOS")
        print("Enter three invalid passwords to get an 8-digit hash, e.g. 03133610")
        in_hash = input("Please enter the hash: ")

    in_hash = in_hash.strip().replace("-", "").replace(" ", "")

    if len(in_hash) != 8 or not in_hash.isdigit():
        print(f"Error: expected exactly 8 digits, got {len(in_hash)!r}: {in_hash!r}")
        return 1

    print("\nThe master password is: " + calc_password(in_hash))
    print("(Encoded for a US QWERTY keyboard layout.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
