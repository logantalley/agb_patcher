#!/usr/bin/env python3
"""
nsui_patch.py - NSUI-compatible GBA sleep patch for 3DS Virtual Console

Replicates the patching strategy used by NSUI (New Super Ultimate Injector):
- Patch 1: ARM sleep entry — replaces BX r1 with STR r0,[r1] to use hardware
            REG_HALTCNT sleep, which the 3DS wakes from automatically on lid open
- Patch 2: ARM wake pointer — replaces high-ROM function pointer with 0x03007FFC
            (GBA interrupt vector) so wake is driven by hardware interrupt
- Patch 3: Thumb wake check NOP (optional — not present in all SDK versions)
- Patch 4: ARM wake pointer near Thumb section (optional)

P1 and P2 are required. P3 and P4 are optional — some ROM SDK versions (including
certain romhacks) do not have the Thumb wake check section at all. P1+P2 alone are
sufficient for correct lid-open wake behavior.

Wake pointers are identified by pointing into the top 2MB of ROM space
(0x09E00000-0x09FFFFFF) where sleep handler code is injected by patching tools.

Idempotent: already-patched ROMs are detected and skipped gracefully.

Usage:
    python3 nsui_patch.py input.gba output.gba
    python3 nsui_patch.py input.gba output.gba --dry-run
"""

import sys
import struct
import argparse

INTERRUPT_VECTOR = b'\xfc\x7f\x00\x03'  # 0x03007FFC — GBA IWRAM interrupt handler
STR_R0_R1        = b'\x00\x00\x81\xe5'  # STR r0,[r1]  — already-patched P1
BX_R1            = b'\x11\xff\x2f\xe1'  # BX r1        — unpatched P1
THUMB_NOP        = b'\x04\x60'          # MOV r0,r0    — already-patched P3
THUMB_BX_R0      = b'\x00\x47'          # BX r0        — unpatched P3
LDR_R0_PC        = b'\x06\x48'          # LDR r0,[pc,#N] — P3 anchor (fixed encoding)

P3_SEARCH_WINDOW = 0x2000


def _find_wake_ptr(data, start, end):
    """
    Scan [start, end) in 4-byte steps for a high-ROM wake pointer
    (0x09E00000-0x09FFFFFF) or an already-patched INTERRUPT_VECTOR.
    Returns (offset, already_patched) or (None, None).
    """
    for j in range(start, end, 4):
        val = struct.unpack('<I', bytes(data[j:j+4]))[0]
        if 0x09E00000 <= val <= 0x09FFFFFF:
            return j, False
        if data[j:j+4] == INTERRUPT_VECTOR:
            return j, True
    return None, None


def apply_nsui_sleep_patch(rom_bytes, verbose=False):
    """
    Apply NSUI-compatible sleep patch to a GBA ROM.
    Idempotent — already-applied patches are detected and skipped.
    P3/P4 are optional and skipped gracefully if not present.

    Returns (patched_bytes, patch_list, skipped_list) on success,
    or raises ValueError with a descriptive message on failure.
    """
    data    = bytearray(rom_bytes)
    patches = []
    skipped = []

    def log(msg):
        if verbose:
            print(f"  {msg}")

    # ------------------------------------------------------------------
    # PATCH 1: ARM sleep entry (REQUIRED)
    # Scan for: ADD r0, pc, #N  (XX 00 8f e2)
    #     then: BX r1           (11 ff 2f e1)   <-- unpatched
    #        or STR r0,[r1]     (00 00 81 e5)   <-- already patched
    # ------------------------------------------------------------------
    p1_offset = None
    for i in range(0, len(data) - 8, 4):
        if data[i+1] == 0x00 and data[i+2] == 0x8f and data[i+3] == 0xe2:
            next4 = bytes(data[i+4:i+8])
            if next4 == BX_R1:
                p1_offset = i + 4
                data[p1_offset:p1_offset+4] = STR_R0_R1
                patches.append(('P1_sleep_entry', p1_offset))
                log(f"P1 @ 0x{p1_offset:08x}: BX r1 -> STR r0,[r1]")
                break
            elif next4 == STR_R0_R1:
                p1_offset = i + 4
                skipped.append(('P1_sleep_entry', p1_offset))
                log(f"P1 @ 0x{p1_offset:08x}: already patched (STR r0,[r1]), skipping")
                break

    if p1_offset is None:
        raise ValueError(
            "P1 not found: ADD r0,pc,#N + (BX r1 or STR r0,[r1]) pattern missing. "
            "Unsupported sleep routine structure.")

    # ------------------------------------------------------------------
    # PATCH 2: ARM wake pointer (REQUIRED)
    # Scan forward from P1 for first high-ROM pointer (0x09E00000-0x09FFFFFF)
    # pointing to injected sleep handler code at end of ROM,
    # or existing INTERRUPT_VECTOR (already patched).
    # Low ROM pointers (0x08000000-0x09DFFFFF) are left alone — they are
    # legitimate game function pointers, not sleep handler pointers.
    # ------------------------------------------------------------------
    p2_off, p2_done = _find_wake_ptr(data, p1_offset + 4, p1_offset + 0x300)
    if p2_off is None:
        raise ValueError(
            "P2 not found: no high-ROM wake pointer (0x09Exxxxx) or existing "
            "0x03007FFC found within 0x300 bytes of P1. "
            "Unsupported sleep routine structure.")
    if p2_done:
        log(f"P2 @ 0x{p2_off:08x}: already patched (0x03007FFC), skipping")
        skipped.append(('P2_wake_ptr', p2_off))
    else:
        val = struct.unpack('<I', bytes(data[p2_off:p2_off+4]))[0]
        log(f"P2 @ 0x{p2_off:08x}: ROM ptr 0x{val:08x} -> 0x03007FFC")
        data[p2_off:p2_off+4] = INTERRUPT_VECTOR
        patches.append(('P2_wake_ptr', p2_off))

    # ------------------------------------------------------------------
    # PATCH 3: Thumb wake check NOP (OPTIONAL)
    # Scan within P3_SEARCH_WINDOW bytes of P1 for:
    #   06 48  (LDR r0, [pc, #N]) — fixed Thumb encoding
    #   00 47  (BX r0)            — unpatched
    #   04 60  (MOV r0,r0 NOP)    — already patched
    # Not present in all SDK versions — failure is non-fatal.
    # ------------------------------------------------------------------
    p3_idx    = None
    p3_offset = None
    search_end = min(p1_offset + P3_SEARCH_WINDOW, len(data) - 4)

    pos = p1_offset
    while pos < search_end:
        idx = bytes(data).find(LDR_R0_PC, pos, search_end)
        if idx == -1:
            break
        suffix = bytes(data[idx+2:idx+4])
        if suffix == THUMB_BX_R0:
            p3_idx    = idx
            p3_offset = idx + 2
            data[p3_offset:p3_offset+2] = THUMB_NOP
            patches.append(('P3_thumb_nop', p3_offset))
            log(f"P3 @ 0x{p3_offset:08x}: BX r0 -> MOV r0,r0 (NOP)")
            break
        elif suffix == THUMB_NOP:
            p3_idx    = idx
            p3_offset = idx + 2
            skipped.append(('P3_thumb_nop', p3_offset))
            log(f"P3 @ 0x{p3_offset:08x}: already patched (NOP), skipping")
            break
        pos = idx + 2

    if p3_idx is None:
        log("P3 not present in this ROM's sleep routine (optional — skipping)")

    # ------------------------------------------------------------------
    # PATCH 4: ARM wake pointer near Thumb section (OPTIONAL)
    # Only attempted if P3 was found.
    # ------------------------------------------------------------------
    if p3_idx is not None:
        p4_off, p4_done = _find_wake_ptr(data, p3_idx + 4, p3_idx + 0x40)
        if p4_off is None:
            log("P4 not found near Thumb section (optional — skipping)")
        elif p4_done:
            log(f"P4 @ 0x{p4_off:08x}: already patched (0x03007FFC), skipping")
            skipped.append(('P4_wake_ptr', p4_off))
        else:
            val = struct.unpack('<I', bytes(data[p4_off:p4_off+4]))[0]
            log(f"P4 @ 0x{p4_off:08x}: ROM ptr 0x{val:08x} -> 0x03007FFC")
            data[p4_off:p4_off+4] = INTERRUPT_VECTOR
            patches.append(('P4_wake_ptr', p4_off))

    return bytes(data), patches, skipped


def main():
    parser = argparse.ArgumentParser(
        description='Apply NSUI-compatible sleep patch to a GBA VC ROM')
    parser.add_argument('input',  help='Input .gba file')
    parser.add_argument('output', help='Output .gba file')
    parser.add_argument('--dry-run', action='store_true',
                        help='Detect patches without writing output')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Print patch locations')
    args = parser.parse_args()

    with open(args.input, 'rb') as f:
        rom = f.read()

    print(f"Input:  {args.input} ({len(rom):,} bytes)")

    try:
        patched, patches, skipped = apply_nsui_sleep_patch(
            rom, verbose=args.verbose or args.dry_run)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    if patches:
        print(f"Applied: {', '.join(f'{n}@{hex(o)}' for n,o in patches)}")
    if skipped:
        print(f"Skipped (already patched): {', '.join(f'{n}@{hex(o)}' for n,o in skipped)}")
    if not patches and not skipped:
        print("WARNING: no patches applied or detected")

    if args.dry_run:
        print("Dry run — no output written.")
        return

    with open(args.output, 'wb') as f:
        f.write(patched)
    print(f"Output: {args.output}")


if __name__ == '__main__':
    main()
