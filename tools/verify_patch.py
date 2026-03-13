#!/usr/bin/env python3
"""
verify_patch.py <patched.gba> [code.bin]

Verifies that nsui_patch.py successfully applied the sleep patch.
With two arguments, also verifies the patch survived the splice into code.bin.
"""
import struct, sys

PATCH_BIN_FIRST8 = bytes([0x01,0x13,0xa0,0xe3, 0x4c,0x00,0x01,0xe5])
IRQ_VECTORS      = [0x03007FFC, 0x03007E40, 0x03007640]
INJECT_TOTAL     = 592   # PAYLOAD_SIZE(548) + STUB_SIZE(40) + PAD(4)
GBA_ROM_BASE     = 0x08000000

def check(label, data, rom_size):
    payload_off = rom_size - INJECT_TOTAL
    stub_off    = rom_size - 40 - 4
    payload_gba = GBA_ROM_BASE + payload_off
    stub_gba    = GBA_ROM_BASE + stub_off

    print(f"[{label}]")
    print(f"  size:            {len(data):,} bytes (0x{len(data):08x})")
    print(f"  payload offset:  0x{payload_off:08x}  (GBA 0x{payload_gba:08x})")
    print(f"  stub offset:     0x{stub_off:08x}  (GBA 0x{stub_gba:08x})")

    # Check payload signature
    got  = bytes(data[payload_off:payload_off+4])
    want = PATCH_BIN_FIRST8[:4]
    ok   = "OK" if got == want else "FAIL"
    print(f"  payload[0:4]:    {got.hex()}  (want {want.hex()})  [{ok}]")

    # Check stub GBA address appears as a data word somewhere in ROM
    # (the patched LDR data word should now contain stub_gba)
    stub_bytes = struct.pack('<I', stub_gba)
    stub_found = False
    pos = 0
    while True:
        pos = data.find(stub_bytes, pos)
        if pos < 0: break
        if pos % 4 == 0:
            stub_found = True
            print(f"  stub ptr found:  at ROM offset 0x{pos:06x} -> 0x{stub_gba:08x}  [OK]")
            break
        pos += 4
    if not stub_found:
        print(f"  stub ptr:        NOT FOUND (0x{stub_gba:08x} not in ROM as data word)  [FAIL]")
        # Show what's at the known IRQ-installer offsets for diagnosis
        for probe in [0x06ec, 0x0b70, 0x021c, 0x0240]:
            if probe + 4 <= len(data):
                v = struct.unpack_from('<I', data, probe)[0]
                print(f"    probe 0x{probe:04x}: 0x{v:08x}")

    # Check BX r0 (0x4700) within 16 bytes before the stub pointer data word
    if stub_found:
        bx_bytes = struct.pack('<H', 0x4700)
        bx_pos = data.rfind(bx_bytes, max(0, pos - 16), pos + 2)
        if bx_pos >= 0:
            print(f"  BX r0 at:        0x{bx_pos:05x}  [OK]")
        else:
            # Wider search — the LDR and BX may not be adjacent
            bx_pos = data.rfind(bx_bytes, max(0, pos - 32), pos + 2)
            if bx_pos >= 0:
                print(f"  BX r0 at:        0x{bx_pos:05x}  [OK]")
            else:
                print(f"  BX r0:           not found near stub ptr  [WARN]")

    print()


rom_path  = sys.argv[1]
cbin_path = sys.argv[2] if len(sys.argv) > 2 else None

with open(rom_path, 'rb') as f:
    rom = f.read()

check("patched ROM", rom, len(rom))

if cbin_path:
    with open(cbin_path, 'rb') as f:
        cb = f.read()
    rom_size = len(rom)
    check("code.bin", cb, rom_size)
    inject = rom_size - INJECT_TOTAL
    match  = bytes(rom[inject:inject+16]) == bytes(cb[inject:inject+16])
    print(f"  splice match:  {'OK' if match else 'FAIL'}")
