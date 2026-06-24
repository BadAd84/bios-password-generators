# bios-password-generators

Offline master-password / "System Disabled" recovery generators for laptop BIOSes,
reverse-engineered from firmware. For use on hardware you own or are authorized to service.

## Generators

### `dell_e4310_2a7b_unlock.py`
Master-password generator for the **Dell Latitude E4310** (Compal LA-5691P / NAL60,
InsydeH2O BIOS) `-2A7B` "System Disabled" code.

Reverse-engineered directly from the machine's own firmware dump — module
`a0b87e92-6392-47fe-9aa0-90203147ec04`, function `sub_0x4e10` — **not** from any
online generator. Algorithm (verbatim from the x86-64 disassembly):

```
tag    = chars shown before "-2A7B"   (sanitized: byte <=0x20 or >0x7e -> '*')
pre8   = transform8(tag)              (base-32 repack + 0xAA-XOR + charset map)
buf    = tag(11) + "2A7B" + pre8      (23 bytes)
master = CHARSET[ MD5(buf)[i] % 72 ]  for i in 0..15      (16-char password)
CHARSET = "012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0"
```

```
python dell_e4310_2a7b_unlock.py XXXXXXXXXXX-2A7B
```

> Status: faithful translation of the firmware routine; not yet validated against a
> known code/master pair. Verify the first result on the machine. The 11-char (HDD/long)
> tag form is fully resolved; the 7-char BIOS-system-password form may need calibration.

### `insyde_unlock.py`
Generic **InsydeH2O** 8-digit-hash master-password generator (Acer/HP/Fujitsu-Siemens
family; salt `Iou|hj&Z`). **Does not apply to the Dell E4310** above — kept only as a
reference implementation of the classic Insyde algorithm.

## Notes
Python 3, standard library only, no network access required. Passwords are encoded for a
US-QWERTY keyboard layout.
