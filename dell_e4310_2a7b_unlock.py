#!/usr/bin/env python3
"""
Dell Latitude E4310 "-2A7B" BIOS/HDD master-password generator.

This is NOT the public Insyde generator. It was reverse-engineered directly from
the machine's own firmware dump (chip U13, InsydeH2O BIOS region), module
a0b87e92-6392-47fe-9aa0-90203147ec04, function sub_0x4e10 + helpers. Every step
below is a faithful translation of that x86-64 code.

Algorithm (exactly as disassembled):
  tag   = the characters shown on screen BEFORE "-2A7B" (11 chars for the HDD /
          long form). Each byte <=0x20 or >0x7e is replaced by '*'  (sanitizer).
  pre8  = transform8(tag)                                 # sub_4a90, arg2=0
  buf   = tag(11) + b"2A7B" + pre8                        # 23 bytes
  digest= MD5(buf)                                        # standard MD5
  master= "".join(CHARSET[digest[i] % 72] for i in range(16))   # 16 chars

CHARSET and the constant 0xAA / modulus 72 (0x48) are taken verbatim from the
binary (.data 0x4f40 and the idiv/xor immediates).

IMPORTANT: produced without a known code/password reference pair, so verify the
first result on the actual machine. If the on-screen tag is not 11 characters
(e.g. a 7-char BIOS service tag), tell me the exact on-screen text first.
"""
import sys, hashlib

# .data @ RVA 0x4f40, exactly 72 bytes (note: '8' is intentionally missing after '7')
CHARSET = b"012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0"
assert len(CHARSET) == 72
SUFFIX = b"2A7B"


def sanitize(buf: bytes) -> bytes:
    # sub_2430 / sub_4da0: byte <=0x20 or >0x7e -> '*' (0x2a)
    return bytes(c if 0x20 < c <= 0x7e else 0x2a for c in buf)


def transform8(tag: bytes) -> bytes:
    """sub_4a90 with arg2 == 0. tag is the 11 sanitized tag bytes.
    Returns 8 bytes (already mapped through CHARSET)."""
    b = [0] * 16
    for i in range(11):
        b[i] = tag[i]
    # head (arg2 == 0 path): only these two writes execute
    b[0xC] = b[0]
    b[0xB] = b[1]
    # source bytes for the repack = b[8..0xC]
    s8, s9, sA, sB, sC = b[8], b[9], b[0xA], b[0xB], b[0xC]
    # 5 bytes -> 8 x 5-bit symbols (exact bit slicing from 0x4afa..0x4c17)
    b[0] = s8 & 0x1F
    b[1] = ((s8 >> 5) | (((s9 << 3) | (s9 >> 5)) & 0xF1)) & 0x1F
    b[2] = (s9 >> 2) & 0x1F
    b[3] = ((s9 >> 7) | ((sA << 1) & 0x1F)) & 0xFF
    b[4] = ((sA >> 4) | ((sB << 4) & 0x1F)) & 0xFF
    b[5] = (sB >> 1) & 0x1F
    b[6] = ((sB >> 6) | ((sC << 2) & 0x1F)) & 0xFF
    b[7] = (sC >> 3) & 0x1F
    # per-symbol loop (0x4c1a..0x4d19)
    out = bytearray()
    for i in range(8):
        sym = b[i]
        t = 0xAA
        if sym & 0x01: t ^= s8
        if sym & 0x02: t ^= s9
        if sym & 0x04: t ^= sA
        if sym & 0x08: t ^= sB
        if sym & 0x10: t ^= sC
        out.append(CHARSET[t % 72])
    return bytes(out)


def master_password(tag: str) -> str:
    tag_b = tag.encode("latin1", "replace")
    if len(tag_b) != 11:
        # pad/trim to 11 to mirror the fixed 11-byte copy; flagged to the user.
        tag_b = (tag_b + b"\x00" * 11)[:11]
    tag_b = sanitize(tag_b)
    buf = tag_b + SUFFIX + transform8(tag_b)      # 11 + 4 + 8 = 23
    digest = hashlib.md5(buf).digest()
    return "".join(chr(CHARSET[digest[i] % 72]) for i in range(16))


def main() -> int:
    if len(sys.argv) > 1:
        code = sys.argv[1]
    else:
        code = input("Enter the on-screen code (e.g. XXXXXXXXXXX-2A7B): ").strip()
    code = code.strip()
    up = code.upper()
    if up.endswith("-2A7B"):      # strip suffix case-insensitively, keep tag case as-is
        tag = code[:-5]
    elif up.endswith("2A7B"):
        tag = code[:-4]
    else:
        tag = code
    print(f"\ntag        : {tag!r}  ({len(tag)} chars)")
    print(f"master(16) : {master_password(tag)}")
    print("\nNote: 16-char master, US-QWERTY. Verify on the machine; if the tag")
    print("isn't 11 chars, send me the exact on-screen text to calibrate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
