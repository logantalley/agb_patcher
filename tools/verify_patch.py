#!/usr/bin/env python3
"""
verify_patch.py <patched.gba> [code.bin]

Called after nsui_patch.py to confirm patch bytes are correct.
With one argument:  verifies the patched ROM file itself.
With two arguments: also verifies the patch survived the splice into code.bin.
"""
import struct, sys

def check(label, data, rom_size):
    inject      = rom_size - 592
    inject_gba  = 0x08000000 + inject
    p4_expected = inject_gba + 0x0224

    print(f"[{label}]")
    print(f"  size:          {len(data)} bytes (0x{len(data):08x})")
    print(f"  inject offset: 0x{inject:08x}")
    print(f"  P4 expected:   0x{p4_expected:08x}")

    payload4 = data[inject:inject+4]
    want     = bytes.fromhex("0113a0e3")
    ok       = "OK" if payload4 == want else "FAIL"
    print(f"  payload[0:4]:  {payload4.hex()}  (want {want.hex()})  [{ok}]")

    ret_off = inject + 0x0244
    if ret_off + 4 <= len(data):
        ret = struct.unpack("<I", data[ret_off:ret_off+4])[0]
        print(f"  payload ret:   0x{ret:08x}")

    # Check P4 pointer at scan offsets
    p4_ok = False
    for off in range(0, min(len(data), 0x80000), 2):
        if data[off+1:off+2] == b'\x48':
            N        = data[off]
            pc       = (off + 4) & ~2
            load_off = pc + N * 4
            if load_off + 4 > len(data):
                continue
            val = struct.unpack("<I", data[load_off:load_off+4])[0]
            if val == p4_expected:
                for j in range(off+2, min(off+10, len(data)-1), 2):
                    if data[j:j+2] == b'\x00\x47':
                        print(f"  P4 at 0x{load_off:08x}: 0x{val:08x}  [OK]")
                        p4_ok = True
                        break
            if p4_ok:
                break
    if not p4_ok:
        print(f"  P4: NOT FOUND with value 0x{p4_expected:08x}")
        for off in [0x06EC, 0x0B70, 0x021C, 0x0240]:
            if off + 4 <= len(data):
                v = struct.unpack("<I", data[off:off+4])[0]
                print(f"    probe 0x{off:04x}: 0x{v:08x}")

rom_path  = sys.argv[1]
cbin_path = sys.argv[2] if len(sys.argv) > 2 else None

with open(rom_path, "rb") as f:
    rom = f.read()
rom_size = len(rom)

check("patched ROM", rom, rom_size)

if cbin_path:
    with open(cbin_path, "rb") as f:
        cb = f.read()
    print()
    check("code.bin", cb, rom_size)
    inject = rom_size - 592
    match  = rom[inject:inject+16] == cb[inject:inject+16]
    print(f"  splice match:  {'OK' if match else 'FAIL'}")
    if not match:
        print(f"    rom:      {rom[inject:inject+16].hex()}")
        print(f"    code.bin: {cb[inject:inject+16].hex()}")
