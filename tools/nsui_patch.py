#!/usr/bin/env python3
"""
nsui_patch.py - GBA CIA sleep patcher (NSUI/sleephack reimplementation)

Fully reverse-engineered from NSUI's sleephack.exe via binary diff of
NSUI-patched vs unpatched GBA ROMs (Pokemon FireRed / Crash Nitro Kart).

MECHANISM:
  The GBA ROM contains a Thumb function that installs the game's IRQ handler
  into IWRAM slot 0x03007FFC, typically:

    LDR r0, [pc, #N]  ; r0 = 0x03007FFC  (IRQ vector address, in data table)
    STR rH, [r0]      ; [0x03007FFC] = rH (install game's handler address)

  NSUI makes exactly two ROM edits:
    1. Data table word:   0x03007FFC -> stub_gba_addr
    2. STR rH,[r0] (2 bytes) -> BX r0 (0x4700)

  And injects two blobs at the last 592 bytes of the ROM
  (overwriting what should be 0xFF padding):
    [ROM_SIZE - 592]: patch.bin (548 bytes) - position-independent ARM sleep handler
    [ROM_SIZE - 44]:  stub (40 bytes) + 4 bytes 0x00 padding to fill 44 bytes

  The 40-byte ARM stub:
    PUSH {r0,r1,r3,r4,r6,r8,r10,lr}
    MOV r12, rH          ; save original handler to r12
    MOV r1, r0           ; r1 = stub address (for patch.bin use)
    MOV r0, r12          ; r0 = original handler (passed to patch.bin init)
    BL patch.bin         ; call patch.bin init
    POP {r0,r1,r3,r4,r6,r8,r10,lr}
    LDR r0,[pc,#0]       ; load return address
    BX r0                ; return to game Thumb code
    .word return_thumb   ; Thumb address of instruction after patched STR
    .word 0x00000000     ; padding

  At runtime:
    - BX r0 diverts game to stub (r0 = stub_gba_addr)
    - Stub calls patch.bin init(r0 = original_handler_addr)
    - patch.bin saves original handler, installs sleep polling at IWRAM 0x03007FA0,
      writes that address to 0x03007FFC, returns via BX lr
    - Stub restores regs, returns to game
    - Every IRQ: IWRAM stub checks L+R+Select, calls SWI 0x03 (BIOS Stop)
    - 3DS GBA VC intercepts SWI 0x03 and suspends the system

SCAN:
  1. Find all ROM data words equal to 0x03007FFC
  2. For each, look for a Thumb LDR r0,[pc,#N] that loads it
  3. Confirm the next Thumb instruction is STR rH,[r0]
  4. Build and inject payload + stub, patch data word and STR instruction

Usage:
  python3 nsui_patch.py <input.gba> <output.gba> [--verbose]
"""

import struct, sys, os, shutil

# ── Payload ───────────────────────────────────────────────────────────────────
PATCH_BIN = bytes([
    0x01,0x13,0xa0,0xe3, 0x4c,0x00,0x01,0xe5, 0x34,0x00,0x8f,0xe2, 0x48,0x00,0x01,0xe5,
    0xec,0x01,0x9f,0xe5, 0x60,0x00,0x01,0xe5, 0xe8,0x01,0x9f,0xe5, 0x5c,0x00,0x01,0xe5,
    0xe4,0x01,0x9f,0xe5, 0x58,0x00,0x01,0xe5, 0xe0,0x01,0x9f,0xe5, 0x54,0x00,0x01,0xe5,
    0xdc,0x01,0x9f,0xe5, 0x50,0x00,0x01,0xe5, 0xd8,0x01,0x9f,0xe5, 0x04,0x00,0x01,0xe5,
    0x1e,0xff,0x2f,0xe1, 0x30,0x21,0x90,0xe5, 0x04,0x30,0x2d,0xe5, 0x04,0x40,0x2d,0xe5,
    0xc4,0x31,0x9f,0xe5, 0x03,0x20,0x02,0xe0, 0x00,0x40,0xa0,0xe3, 0x00,0x40,0x84,0xe3,
    0x00,0x40,0x84,0xe3, 0x04,0x40,0x84,0xe3, 0x00,0x40,0x84,0xe3, 0x00,0x40,0x84,0xe3,
    0x00,0x40,0x84,0xe3, 0x00,0x40,0x84,0xe3, 0x00,0x40,0x84,0xe3, 0x01,0x4c,0x84,0xe3,
    0x02,0x4c,0x84,0xe3, 0x03,0x40,0x24,0xe0, 0x04,0x00,0x52,0xe1, 0x04,0x40,0x9d,0xe4,
    0x04,0x30,0x9d,0xe4, 0x14,0x00,0x00,0x0a, 0x04,0x30,0x2d,0xe5, 0x04,0x40,0x2d,0xe5,
    0x74,0x31,0x9f,0xe5, 0x00,0x40,0xa0,0xe3, 0x00,0x40,0x84,0xe3, 0x00,0x40,0x84,0xe3,
    0x04,0x40,0x84,0xe3, 0x08,0x40,0x84,0xe3, 0x00,0x40,0x84,0xe3, 0x00,0x40,0x84,0xe3,
    0x00,0x40,0x84,0xe3, 0x00,0x40,0x84,0xe3, 0x01,0x4c,0x84,0xe3, 0x02,0x4c,0x84,0xe3,
    0x03,0x40,0x24,0xe0, 0x04,0x00,0x52,0xe1, 0x04,0x40,0x9d,0xe4, 0x04,0x30,0x9d,0xe4,
    0x00,0x00,0xa0,0xe1, 0x4c,0xf0,0x10,0x15, 0x00,0x00,0x26,0xef, 0xf0,0x4f,0x2d,0xe9,
    0x60,0x10,0x80,0xe2, 0xfc,0x03,0xb1,0xe8, 0xfc,0x03,0x2d,0xe9, 0xfc,0x03,0xb1,0xe8,
    0xfc,0x03,0x2d,0xe9, 0x02,0x1c,0x80,0xe2, 0xb0,0x40,0xd1,0xe1, 0x30,0x51,0x90,0xe5,
    0xb0,0x60,0xd0,0xe1, 0x04,0x11,0x9f,0xe5, 0x00,0x12,0x80,0xe5, 0x03,0x89,0xa0,0xe3,
    0x00,0x80,0x88,0xe3, 0x00,0x80,0x88,0xe3, 0x04,0x80,0x88,0xe3, 0x08,0x80,0x88,0xe3,
    0x00,0x80,0x88,0xe3, 0x00,0x80,0x88,0xe3, 0x00,0x80,0x88,0xe3, 0x00,0x80,0x88,0xe3,
    0x00,0x80,0x88,0xe3, 0x00,0x80,0x88,0xe3, 0x08,0x88,0xa0,0xe1, 0x30,0x81,0x80,0xe5,
    0xb4,0x08,0xc0,0xe1, 0x80,0x10,0x86,0xe3, 0xb0,0x10,0xc0,0xe1, 0x00,0x00,0x03,0xef,
    0xb4,0x70,0x9f,0xe5, 0x28,0x88,0xa0,0xe1, 0x07,0x80,0x08,0xe0, 0x01,0x03,0xa0,0xe3,
    0x30,0x11,0x90,0xe5, 0x08,0x10,0x01,0xe0, 0x08,0x00,0x51,0xe1, 0xfa,0xff,0xff,0x1a,
    0xb6,0x10,0xd0,0xe1, 0x9f,0x00,0x51,0xe3, 0xfc,0xff,0xff,0x1a, 0xb6,0x10,0xd0,0xe1,
    0xa0,0x00,0x51,0xe3, 0xfc,0xff,0xff,0x1a, 0xb6,0x10,0xd0,0xe1, 0x9f,0x00,0x51,0xe3,
    0xfc,0xff,0xff,0x1a, 0xb6,0x10,0xd0,0xe1, 0xa0,0x00,0x51,0xe3, 0xfc,0xff,0xff,0x1a,
    0xb6,0x10,0xd0,0xe1, 0x9f,0x00,0x51,0xe3, 0xfc,0xff,0xff,0x1a, 0x02,0x1c,0x80,0xe2,
    0xb0,0x40,0xc1,0xe1, 0x30,0x51,0x80,0xe5, 0x01,0x4a,0xa0,0xe3, 0xb2,0x40,0xc1,0xe1,
    0xb0,0x60,0xc0,0xe1, 0xfc,0x03,0xbd,0xe8, 0x84,0x30,0x80,0xe5, 0x80,0x10,0x80,0xe2,
    0xfc,0x03,0xa1,0xe8, 0x60,0x10,0x80,0xe2, 0xfc,0x03,0xbd,0xe8, 0xfc,0x03,0xa1,0xe8,
    0xf0,0x4f,0xbd,0xe8, 0xb6,0x10,0xd0,0xe1, 0xa0,0x00,0x51,0xe3, 0xfc,0xff,0xff,0x1a,
    0x4c,0xf0,0x10,0xe5, 0x00,0x12,0x90,0xe5, 0x01,0x08,0x11,0xe3, 0x01,0x02,0x11,0x03,
    0x4c,0xf0,0x10,0x05, 0x48,0xf0,0x10,0xe5, 0xa0,0x7f,0x00,0x03, 0xff,0x03,0x00,0x00,
    0x00,0x30,0xff,0xff,
])
assert len(PATCH_BIN) == 548

PAYLOAD_SIZE     = 548
STUB_SIZE        = 40    # 10 ARM words
STUB_PAD         = 4     # zero-padding after stub
INJECT_TOTAL     = PAYLOAD_SIZE + STUB_SIZE + STUB_PAD  # = 592 bytes from ROM end
GBA_ROM_BASE     = 0x08000000


# ── Stub builder ──────────────────────────────────────────────────────────────

def build_stub(handler_reg: int, payload_gba: int, return_thumb_gba: int) -> bytes:
    """
    Build the 40-byte ARM trampoline stub.

    handler_reg:       register number (0-7) holding game's original IRQ handler
    payload_gba:       GBA address of patch.bin (= GBA_ROM_BASE + payload_rom_off)
    return_thumb_gba:  Thumb GBA address to return to (= next instr ROM addr | 1)
    """
    reglist = 0x543f   # {r0,r1,r3,r4,r6,r8,r10,lr} — matches NSUI's observed stub

    push_instr = 0xe92d0000 | reglist       # PUSH (STMDB sp!)
    pop_instr  = 0xe8bd0000 | reglist       # POP  (LDMIA sp!)
    mov_r12_rh = 0xe1a0c000 | handler_reg   # MOV r12, rH
    mov_r1_r0  = 0xe1a01000                 # MOV r1, r0
    mov_r0_r12 = 0xe1a0000c                 # MOV r0, r12

    # BL is the 5th instruction in stub (offset 4*4=16 from stub start)
    stub_gba   = payload_gba + PAYLOAD_SIZE
    bl_from    = stub_gba + 4 * 4           # address of BL instruction
    bl_offset  = (payload_gba - (bl_from + 8)) >> 2
    bl_instr   = 0xeb000000 | (bl_offset & 0xFFFFFF)

    ldr_r0_pc0 = 0xe59f0000                 # LDR r0,[pc,#0]
    bx_r0      = 0xe12fff10                 # BX r0

    stub = struct.pack('<10I',
        push_instr,
        mov_r12_rh,
        mov_r1_r0,
        mov_r0_r12,
        bl_instr,
        pop_instr,
        ldr_r0_pc0,
        bx_r0,
        return_thumb_gba,
        0x00000000,
    )
    assert len(stub) == STUB_SIZE
    return stub


# ── Thumb decoder helpers ─────────────────────────────────────────────────────

def thumb_ldr_r0_pc_target(hw: int, instr_off: int):
    """If hw is Thumb LDR r0,[pc,#imm8*4], return target ROM offset; else None."""
    if (hw & 0xF800) != 0x4800:
        return None
    if (hw >> 8) & 0x7 != 0:   # Rd must be r0
        return None
    imm8 = hw & 0xFF
    pc_align = (instr_off + 4) & ~3
    return pc_align + imm8 * 4


def thumb_str_rh_r0(hw: int):
    """
    If hw is Thumb STR rH,[r0,#0] (format 0x6000|rH, rH in 0-7), return rH; else None.
    Encoding: 0110 0 00000 000 rH  (imm5=0, Rn=r0)
    """
    if (hw & 0xFFF8) == 0x6000:
        return hw & 0x7
    return None


# ── Hook finder ───────────────────────────────────────────────────────────────

def find_irq_hook(rom: bytes):
    """
    Scan ROM for the Thumb sequence:
        LDR r0,[pc,#N]   ; loads IRQ vector address from data table
        STR rH,[r0]      ; installs game's handler into that vector slot

    Searches for all known GBA IRQ vector addresses:
        0x03007FFC  standard SDK (FireRed, Ruby, most retail)
        0x03007E40  Emerald and Emerald-based hacks
        0x03007640  some other titles

    Returns (data_word_off, str_instr_off, handler_reg, return_thumb_gba).
    Raises RuntimeError if not found.
    """
    # Known IRQ vector slot addresses used across GBA titles
    IRQ_VECTOR_CANDIDATES = [
        0x03007FFC,  # Standard SDK
        0x03007E40,  # Emerald / Emerald hacks
        0x03007640,  # Other titles
    ]

    data_offs = []
    for vec_addr in IRQ_VECTOR_CANDIDATES:
        needle = struct.pack('<I', vec_addr)
        pos = 0
        while True:
            pos = rom.find(needle, pos)
            if pos < 0:
                break
            if pos % 4 == 0:
                data_offs.append((pos, vec_addr))
            pos += 4

    if not data_offs:
        raise RuntimeError(
            "No known IRQ vector address found as a data word "
            "(tried 0x03007FFC, 0x03007E40, 0x03007640) — "
            "ROM may already be patched or uses an unknown IRQ vector address."
        )

    for data_off, vec_addr in data_offs:
        # Scan Thumb instructions that could LDR from data_off
        # LDR r0,[pc,#imm8*4]: imm8 up to 255 words (1020 bytes) ahead of PC
        search_start = max(0, data_off - 1020)
        for ldr_off in range(search_start, data_off, 2):
            if ldr_off + 4 > len(rom):
                break
            hw = struct.unpack_from('<H', rom, ldr_off)[0]
            if thumb_ldr_r0_pc_target(hw, ldr_off) != data_off:
                continue
            # Check next 2-byte instruction for STR rH,[r0]
            str_off = ldr_off + 2
            str_hw  = struct.unpack_from('<H', rom, str_off)[0]
            handler_reg = thumb_str_rh_r0(str_hw)
            if handler_reg is None:
                continue
            # Found!
            return_thumb_gba = GBA_ROM_BASE + str_off + 2 + 1  # next instr | 1 = Thumb
            return (data_off, vec_addr, str_off, handler_reg, return_thumb_gba)

    raise RuntimeError(
        "Could not find Thumb IRQ installer hook — "
        "searched for LDR r0,[pc,#N] (where [N] is 0x03007FFC / 0x03007E40 / 0x03007640) "
        "followed by STR rH,[r0]. "
        "ROM may use an unknown IRQ vector address."
    )


def is_already_patched(rom: bytes) -> bool:
    """
    True if none of the known IRQ vector addresses remain as data words
    AND payload bytes are present at ROM_SIZE-592.
    """
    IRQ_VECTOR_CANDIDATES = [0x03007FFC, 0x03007E40, 0x03007640]
    for vec_addr in IRQ_VECTOR_CANDIDATES:
        needle = struct.pack('<I', vec_addr)
        pos = 0
        while True:
            pos = rom.find(needle, pos)
            if pos < 0:
                break
            if pos % 4 == 0:
                return False   # still present — not yet patched
            pos += 4
    # None found — check payload signature
    payload_off = len(rom) - INJECT_TOTAL
    if payload_off >= 0 and rom[payload_off:payload_off+8] == PATCH_BIN[:8]:
        return True
    return False


# ── Main patcher ──────────────────────────────────────────────────────────────

def patch_rom(rom: bytes, verbose: bool = False) -> bytes:
    """
    Apply NSUI-style sleep patch to a GBA ROM.
    Returns patched bytes (same size as input).
    Raises RuntimeError for incompatible ROMs.
    """
    rom = bytearray(rom)
    rom_size = len(rom)

    # Idempotency
    if is_already_patched(rom):
        if verbose:
            print("  Already patched — nothing to do.")
        return bytes(rom)

    # Find hook site
    data_off, vec_addr, str_off, handler_reg, return_thumb_gba = find_irq_hook(rom)

    if verbose:
        print(f"  IRQ vector (0x{vec_addr:08x}) at: 0x{data_off:06x}")
        print(f"  STR r{handler_reg},[r0] at:         0x{str_off:05x}")
        print(f"  Return Thumb addr:          0x{return_thumb_gba:08x}")

    # Injection layout: [payload_548][stub_40][pad_4] at ROM end (overwrite 0xFF padding)
    payload_off = rom_size - INJECT_TOTAL           # ROM_SIZE - 592
    stub_off    = payload_off + PAYLOAD_SIZE        # ROM_SIZE - 44
    payload_gba = GBA_ROM_BASE + payload_off
    stub_gba    = GBA_ROM_BASE + stub_off

    # Sanity: the area we're overwriting should be 0xFF padding
    area = bytes(rom[payload_off:rom_size])
    non_ff = sum(1 for b in area if b != 0xFF)
    if non_ff > 0 and verbose:
        print(f"  WARNING: {non_ff} non-0xFF bytes in injection area — may overwrite game data!")

    if verbose:
        print(f"  Payload at ROM offset:   0x{payload_off:06x} (GBA 0x{payload_gba:08x})")
        print(f"  Stub at ROM offset:      0x{stub_off:06x} (GBA 0x{stub_gba:08x})")

    # Build stub
    stub = build_stub(handler_reg, payload_gba, return_thumb_gba)

    # Inject: overwrite last 592 bytes of ROM
    rom[payload_off : payload_off + PAYLOAD_SIZE] = PATCH_BIN
    rom[stub_off    : stub_off    + STUB_SIZE    ] = stub
    rom[stub_off + STUB_SIZE : rom_size          ] = b'\x00' * STUB_PAD

    # Patch 1: data word 0x03007FFC -> stub_gba
    struct.pack_into('<I', rom, data_off, stub_gba)

    # Patch 2: STR rH,[r0] -> BX r0
    struct.pack_into('<H', rom, str_off, 0x4700)

    if verbose:
        print(f"  Data word @ 0x{data_off:06x}: 0x{vec_addr:08x} -> 0x{stub_gba:08x}")
        print(f"  Instr @ 0x{str_off:05x}:  STR r{handler_reg},[r0] -> BX r0")
        print("  Patched an interrupt installer!")

    assert len(rom) == rom_size, "ROM size changed — this is a bug!"
    return bytes(rom)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Apply NSUI-compatible GBA sleep patch')
    parser.add_argument('input',  help='Input .gba ROM file')
    parser.add_argument('output', help='Output patched .gba ROM file')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: {args.input}: not found", file=sys.stderr)
        sys.exit(1)

    with open(args.input, 'rb') as f:
        rom = f.read()

    if args.verbose:
        title = rom[0xa0:0xac].decode('ascii', errors='replace').rstrip('\x00')
        code  = rom[0xac:0xb0].decode('ascii', errors='replace')
        print(f"ROM: {title} ({code}), {len(rom):,} bytes")

    try:
        patched = patch_rom(rom, verbose=args.verbose)
    except RuntimeError as e:
        print(f"SKIP: {e}", file=sys.stderr)
        shutil.copy2(args.input, args.output)
        sys.exit(0)

    with open(args.output, 'wb') as f:
        f.write(patched)

    if args.verbose:
        print(f"Written: {args.output}")


if __name__ == '__main__':
    main()
