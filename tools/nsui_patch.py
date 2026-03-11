#!/usr/bin/env python3
"""
nsui_patch.py - NSUI-compatible GBA sleep patch for 3DS Virtual Console

Replicates the exact patching strategy used by NSUI (New Super Ultimate Injector).

For each GBA VC ROM this script makes up to 4 changes:

  P1  ARM sleep entry:   ADD r0,pc,#N + BX r1  ->  STR r0,[r1]
      Triggers hardware sleep via REG_HALTCNT instead of a software handler.

  P2  ARM wake pointer:  high-ROM ptr (0x09Exxxxx)  ->  0x03007FFC
      Points the wake-return vector at GBA's interrupt vector (hardware wake).

  P4  Thumb wake pointer:  high-ROM ptr loaded by LDR r0,[pc,#N]
      Set to inject_gba_base + 0x0224 (the injected payload entry point).
      The LDR r0,[pc,#N] + BX r0 is left INTACT — BX r0 calls the payload.

  INJ NSUI sleep handler:  590 bytes at rom_size - 592
      Placed so that it ends at rom[-2]. Two fields are updated per-ROM:
      - Payload[0x0244]: Thumb return addr = (P4_ldr_offset + 4) | 0x08000001
        i.e. the instruction after BX r0 in the game's Thumb wake dispatcher.
      - P4 is set to inject_gba_base + 0x0224 (the payload entry point).

P1/P2 are required. P4/INJ are optional — not all SDK versions use them.
Idempotent: already-patched ROMs are detected and skipped gracefully.

Usage:
    python3 nsui_patch.py input.gba output.gba [--verbose] [--dry-run]
"""

import sys, struct, argparse

# ── Constants ─────────────────────────────────────────────────────────────────

INTERRUPT_VECTOR = b'\xfc\x7f\x00\x03'   # 0x03007FFC
STR_R0_R1        = b'\x00\x00\x81\xe5'   # STR r0,[r1]  (P1 patched state)
BX_R1            = b'\x11\xff\x2f\xe1'   # BX r1        (P1 unpatched)
THUMB_BX_R0      = b'\x00\x47'           # BX r0

# NSUI's 590-byte sleep handler payload (position-independent ARM code + data table).
# Two fields are written per-ROM after injection (see PAYLOAD_RET_OFF, PAYLOAD_ENTRY_OFF).
# The word at PAYLOAD_RET_OFF is zeroed in this template; it is set to the game-specific
# Thumb return address before the payload is written to the ROM.
NSUI_PAYLOAD = bytes.fromhex(
    '0113a0e34c0001e534008fe2480001e5ec019fe5600001e5e8019fe55c0001e5'
    'e4019fe5580001e5e0019fe5540001e5dc019fe5500001e5d8019fe5040001e5'
    '1eff2fe1302190e504302de504402de5c4319fe5032002e00040a0e3004084e3'
    '004084e3044084e3004084e3004084e3004084e3004084e3004084e3014c84e3'
    '024c84e3034024e0040052e104409de404309de41400000a04302de504402de5'
    '74319fe50040a0e3004084e3004084e3044084e3084084e3004084e3004084e3'
    '004084e3004084e3014c84e3024c84e3034024e0040052e104409de404309de4'
    '0000a0e14cf01015000026eff04f2de9601080e2fc03b1e8fc032de9fc03b1e8'
    'fc032de9021c80e2b040d1e1305190e5b060d0e104119fe5001280e50389a0e3'
    '008088e3008088e3048088e3088088e3008088e3008088e3008088e3008088e3'
    '008088e3008088e30888a0e1308180e5b408c0e1801086e3b010c0e1000003ef'
    'b4709fe52888a0e1078008e00103a0e3301190e5081001e0080051e1faffff1a'
    'b610d0e19f0051e3fcffff1ab610d0e1a00051e3fcffff1ab610d0e19f0051e3'
    'fcffff1ab610d0e1a00051e3fcffff1ab610d0e19f0051e3fcffff1a021c80e2'
    'b040c1e1305180e5014aa0e3b240c1e1b060c0e1fc03bde8843080e5801080e2'
    'fc03a1e8601080e2fc03bde8fc03a1e8f04fbde8b610d0e1a00051e3fcffff1a'
    '4cf010e5001290e5010811e301021103'
    '4cf0100548f010e5a07f0003ff030000'
    '0030ffff'
    '3f542de904c0a0e10010a0e10c00a0e171ffffeb3f54bde800009fe510ff2fe1'
    '00000000'  # <- PAYLOAD_RET_OFF 0x0244: game-specific Thumb return addr (zeroed in template)
    '000000000000'
)

PAYLOAD_RET_OFF   = 0x0244  # offset within payload of the game-specific return addr
PAYLOAD_ENTRY_OFF = 0x0224  # offset within payload of the callable entry point

assert len(NSUI_PAYLOAD) == 590, f"Payload length mismatch: {len(NSUI_PAYLOAD)}"

# ── Helpers ───────────────────────────────────────────────────────────────────

def _u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def _w32(data, off, val):
    struct.pack_into('<I', data, off, val)

def _find_arm_wake_ptr(data, start, end):
    """Find first high-ROM wake pointer or already-patched 0x03007FFC after P1."""
    for j in range(start, min(end, len(data) - 4), 4):
        val = _u32(data, j)
        if 0x09E00000 <= val <= 0x09FFFFFF:
            return j, False
        if data[j:j+4] == INTERRUPT_VECTOR:
            return j, True
    return None, None

# ── Main patch ────────────────────────────────────────────────────────────────

def apply_nsui_sleep_patch(rom_bytes, verbose=False):
    """
    Apply NSUI-compatible sleep patch to a GBA VC ROM.
    Returns (patched_bytes, applied_list, skipped_list).
    Raises ValueError if P1 or P2 cannot be found.
    """
    data    = bytearray(rom_bytes)
    applied = []
    skipped = []

    def log(msg):
        if verbose:
            print(f"  {msg}")

    # ── P1: ARM sleep entry (required) ───────────────────────────────────────
    # Scan for ADD r0,pc,#N (XX 00 8F E2) immediately followed by BX r1 or STR r0,[r1]
    p1_offset = None
    for i in range(0, len(data) - 8, 4):
        if data[i+1] == 0x00 and data[i+2] == 0x8f and data[i+3] == 0xe2:
            nxt = bytes(data[i+4:i+8])
            if nxt == BX_R1:
                p1_offset = i + 4
                data[p1_offset:p1_offset+4] = STR_R0_R1
                applied.append(('P1_sleep_entry', p1_offset))
                log(f"P1 @ 0x{p1_offset:08x}: BX r1 -> STR r0,[r1]")
                break
            elif nxt == STR_R0_R1:
                p1_offset = i + 4
                skipped.append(('P1_sleep_entry', p1_offset))
                log(f"P1 @ 0x{p1_offset:08x}: already patched")
                break

    if p1_offset is None:
        raise ValueError("P1 not found: ADD r0,pc,#N + BX r1 pattern missing.")

    # ── P2: ARM wake pointer (required) ──────────────────────────────────────
    p2_off, p2_done = _find_arm_wake_ptr(data, p1_offset + 4, p1_offset + 0x300)
    if p2_off is None:
        raise ValueError("P2 not found: no high-ROM wake pointer in 0x300 bytes after P1.")
    if p2_done:
        skipped.append(('P2_wake_ptr', p2_off))
        log(f"P2 @ 0x{p2_off:08x}: already patched")
    else:
        log(f"P2 @ 0x{p2_off:08x}: 0x{_u32(data,p2_off):08x} -> 0x03007FFC")
        data[p2_off:p2_off+4] = INTERRUPT_VECTOR
        applied.append(('P2_wake_ptr', p2_off))

    # ── P4/INJ: Thumb wake pointer + payload injection (optional) ────────────
    # Scan whole ROM for: NN 48 (Thumb LDR r0,[pc,#N]) where the word-aligned
    # load address holds a 0x09Exxxxx high-ROM pointer (or already the payload entry),
    # followed within 8 bytes by 00 47 (BX r0).
    # NOTE: BX r0 is NOT patched — it must remain to call the injected payload.
    inject_file  = len(data) - 592
    inject_gba   = 0x08000000 + inject_file
    p4_correct   = inject_gba + PAYLOAD_ENTRY_OFF

    p4_ldr_off  = None   # file offset of the LDR r0,[pc,#N] instruction
    p4_ptr_off  = None   # file offset of the pointer word that LDR loads
    p4_bxr0_off = None   # file offset of the BX r0 instruction
    p4_done     = False

    for i in range(0, len(data) - 4, 2):
        if data[i+1] != 0x48:
            continue
        N        = data[i]
        pc_thumb = (i + 4) & ~2
        ptr_off  = pc_thumb + N * 4
        if ptr_off + 4 > len(data):
            continue
        loaded = _u32(data, ptr_off)
        is_high    = 0x09E00000 <= loaded <= 0x09FFFFFF
        is_correct = (loaded == p4_correct)
        if not (is_high or is_correct):
            continue
        # Look for BX r0 within next 8 bytes
        for j in range(i + 2, min(i + 10, len(data) - 1), 2):
            if data[j:j+2] == THUMB_BX_R0:
                p4_ldr_off  = i
                p4_ptr_off  = ptr_off
                p4_bxr0_off = j
                p4_done     = is_correct
                break
        if p4_bxr0_off is not None:
            break

    if p4_bxr0_off is not None:
        # P4: update the pointer word that the LDR loads
        if p4_done:
            skipped.append(('P4_wake_ptr', p4_ptr_off))
            log(f"P4 @ 0x{p4_ptr_off:08x}: already correct (0x{p4_correct:08x})")
        else:
            old_val = _u32(data, p4_ptr_off)
            _w32(data, p4_ptr_off, p4_correct)
            applied.append(('P4_wake_ptr', p4_ptr_off))
            log(f"P4 @ 0x{p4_ptr_off:08x}: 0x{old_val:08x} -> 0x{p4_correct:08x}")

        # INJ: inject payload at end of ROM
        already_injected = (data[inject_file:inject_file+4] == NSUI_PAYLOAD[:4])
        if already_injected:
            skipped.append(('payload_inject', inject_file))
            log(f"Payload @ 0x{inject_file:08x}: already present, updating ret addr")
        else:
            data[inject_file:inject_file+len(NSUI_PAYLOAD)] = NSUI_PAYLOAD
            applied.append(('payload_inject', inject_file))
            log(f"Payload @ 0x{inject_file:08x}: injected {len(NSUI_PAYLOAD)} bytes")

        # Set game-specific return address: Thumb addr of instruction after BX r0
        ret_addr = (p4_bxr0_off + 2) | 0x08000001
        _w32(data, inject_file + PAYLOAD_RET_OFF, ret_addr)
        log(f"Payload ret addr @ +0x{PAYLOAD_RET_OFF:04x}: 0x{ret_addr:08x}")
    else:
        log("P4/INJ not present in this ROM's sleep routine (optional)")

    return bytes(data), applied, skipped

# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Apply NSUI-compatible sleep patch to a GBA VC ROM')
    parser.add_argument('input')
    parser.add_argument('output')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    with open(args.input, 'rb') as f:
        rom = f.read()
    print(f"Input:  {args.input} ({len(rom):,} bytes)")

    try:
        patched, applied, skipped = apply_nsui_sleep_patch(
            rom, verbose=args.verbose or args.dry_run)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    if applied:
        print(f"Applied:  {', '.join(f'{n}@{hex(o)}' for n,o in applied)}")
    if skipped:
        print(f"Skipped:  {', '.join(f'{n}@{hex(o)}' for n,o in skipped)}")
    if not applied and not skipped:
        print("WARNING: no patches applied or detected")

    if args.dry_run:
        print("Dry run — no output written.")
        return

    with open(args.output, 'wb') as f:
        f.write(patched)
    print(f"Output: {args.output}")

if __name__ == '__main__':
    main()
