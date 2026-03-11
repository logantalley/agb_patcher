#!/usr/bin/env python3
"""
nsui_patch.py - NSUI-compatible GBA sleep patch for 3DS Virtual Console

Handles two SDK variants of the GBA VC sleep routine:

SDK VARIANT A (most retail games):
  Sleep entry: ADD r0,pc,#N + BX r1  ->  STR r0,[r1]
  Wake ptrs:   high-ROM pointers (0x09Exxxxx) -> 0x03007FFC
  Thumb check: LDR r0,[pc] + BX r0   ->  NOP

SDK VARIANT B (some romhacks / different SDK version):
  Sleep entry: MOV r14,pc + BX r1    ->  MOV pc,lr
  (The routine already uses STR->HALTCNT; we skip the wake handler call instead)
  No wake pointers or Thumb section needed.

Both variants result in hardware sleep that the 3DS wakes automatically on lid open.

Idempotent: already-patched ROMs are detected and skipped gracefully.

Usage:
    python3 nsui_patch.py input.gba output.gba
    python3 nsui_patch.py input.gba output.gba --dry-run
"""

import sys
import struct
import argparse

INTERRUPT_VECTOR = b'\xfc\x7f\x00\x03'  # 0x03007FFC
STR_R0_R1        = b'\x00\x00\x81\xe5'  # STR r0,[r1]  — Variant A P1 patched
BX_R1            = b'\x11\xff\x2f\xe1'  # BX r1
MOV_R14_PC       = b'\x0f\xe0\xa0\xe1'  # MOV r14,pc   — Variant B anchor
MOV_PC_LR        = b'\x0e\xf0\xa0\xe1'  # MOV pc,lr    — Variant B patch
THUMB_NOP        = b'\x04\x60'
THUMB_BX_R0      = b'\x00\x47'
LDR_R0_PC        = b'\x06\x48'
ADD_R0_PC_MASK   = (0x00, 0x8f, 0xe2)   # bytes [1],[2],[3] of ADD r0,pc,#N

P3_SEARCH_WINDOW = 0x2000


def _find_wake_ptr(data, start, end):
    for j in range(start, min(end, len(data) - 4), 4):
        val = struct.unpack('<I', bytes(data[j:j+4]))[0]
        if 0x09E00000 <= val <= 0x09FFFFFF:
            return j, False
        if data[j:j+4] == INTERRUPT_VECTOR:
            return j, True
    return None, None


def apply_nsui_sleep_patch(rom_bytes, verbose=False):
    """
    Apply NSUI-compatible sleep patch to a GBA ROM.
    Detects SDK variant automatically.
    Returns (patched_bytes, patch_list, skipped_list).
    Raises ValueError if no supported sleep routine is found.
    """
    data    = bytearray(rom_bytes)
    patches = []
    skipped = []

    def log(msg):
        if verbose:
            print(f"  {msg}")

    # ----------------------------------------------------------------
    # Detect SDK variant by scanning for both anchor patterns
    # Variant A: ADD r0,pc,#N  (XX 00 8f e2)  then BX r1 or STR r0,[r1]
    # Variant B: MOV r14,pc    (0f e0 a0 e1)  then BX r1 or MOV pc,lr
    # ----------------------------------------------------------------
    variant   = None
    p1_offset = None

    for i in range(0, len(data) - 8, 4):
        b1, b2, b3 = data[i+1], data[i+2], data[i+3]
        next4 = bytes(data[i+4:i+8])

        # Variant A anchor: ADD r0, pc, #N
        if b1 == 0x00 and b2 == 0x8f and b3 == 0xe2:
            if next4 == BX_R1:
                variant   = 'A'
                p1_offset = i + 4
                data[p1_offset:p1_offset+4] = STR_R0_R1
                patches.append(('P1_sleep_entry', p1_offset))
                log(f"P1 [Variant A] @ 0x{p1_offset:08x}: BX r1 -> STR r0,[r1]")
                break
            elif next4 == STR_R0_R1:
                variant   = 'A'
                p1_offset = i + 4
                skipped.append(('P1_sleep_entry', p1_offset))
                log(f"P1 [Variant A] @ 0x{p1_offset:08x}: already patched, skipping")
                break

        # Variant B anchor: STR r0,[r1] two instructions before MOV r14,pc + BX r1
        # The STR is what puts the GBA into hardware sleep; MOV+BX is the wake poll call
        if (bytes(data[i:i+4]) == MOV_R14_PC and
                i >= 8 and bytes(data[i-8:i-4]) == STR_R0_R1):
            if next4 == BX_R1:
                variant   = 'B'
                p1_offset = i + 4
                data[p1_offset:p1_offset+4] = MOV_PC_LR
                patches.append(('P1_sleep_entry', p1_offset))
                log(f"P1 [Variant B] @ 0x{p1_offset:08x}: BX r1 -> MOV pc,lr")
                break
            elif next4 == MOV_PC_LR:
                variant   = 'B'
                p1_offset = i + 4
                skipped.append(('P1_sleep_entry', p1_offset))
                log(f"P1 [Variant B] @ 0x{p1_offset:08x}: already patched, skipping")
                break

    if p1_offset is None:
        raise ValueError(
            "No supported sleep routine found. "
            "Neither Variant A (ADD r0,pc + BX r1) nor "
            "Variant B (MOV r14,pc + BX r1) pattern detected.")

    log(f"SDK Variant: {variant}")

    # Variant B is complete after P1 — the routine already uses hardware
    # sleep via STR->HALTCNT; patching BX r1->MOV pc,lr skips the
    # button-polling wake handler and lets hardware wake handle everything.
    if variant == 'B':
        return bytes(data), patches, skipped

    # ----------------------------------------------------------------
    # Variant A only: P2, P3, P4
    # ----------------------------------------------------------------

    # P2: first high-ROM wake pointer after P1 (required)
    p2_off, p2_done = _find_wake_ptr(data, p1_offset + 4, p1_offset + 0x300)
    if p2_off is None:
        raise ValueError(
            "P2 not found: no high-ROM wake pointer (0x09Exxxxx) or "
            "0x03007FFC within 0x300 bytes of P1.")
    if p2_done:
        log(f"P2 @ 0x{p2_off:08x}: already patched (0x03007FFC), skipping")
        skipped.append(('P2_wake_ptr', p2_off))
    else:
        val = struct.unpack('<I', bytes(data[p2_off:p2_off+4]))[0]
        log(f"P2 @ 0x{p2_off:08x}: ROM ptr 0x{val:08x} -> 0x03007FFC")
        data[p2_off:p2_off+4] = INTERRUPT_VECTOR
        patches.append(('P2_wake_ptr', p2_off))

    # P3: Thumb BX r0 -> NOP (optional)
    p3_idx    = None
    search_end = min(p1_offset + P3_SEARCH_WINDOW, len(data) - 4)
    pos = p1_offset
    while pos < search_end:
        idx = bytes(data).find(LDR_R0_PC, pos, search_end)
        if idx == -1:
            break
        suffix = bytes(data[idx+2:idx+4])
        if suffix == THUMB_BX_R0:
            p3_idx = idx
            data[idx+2:idx+4] = THUMB_NOP
            patches.append(('P3_thumb_nop', idx+2))
            log(f"P3 @ 0x{idx+2:08x}: BX r0 -> NOP")
            break
        elif suffix == THUMB_NOP:
            p3_idx = idx
            skipped.append(('P3_thumb_nop', idx+2))
            log(f"P3 @ 0x{idx+2:08x}: already patched, skipping")
            break
        pos = idx + 2

    if p3_idx is None:
        log("P3 not present in this ROM's sleep routine (optional)")

    # P4: second high-ROM wake pointer near Thumb section (optional)
    if p3_idx is not None:
        p4_off, p4_done = _find_wake_ptr(data, p3_idx + 4, p3_idx + 0x40)
        if p4_off is None:
            log("P4 not found near Thumb section (optional)")
        elif p4_done:
            log(f"P4 @ 0x{p4_off:08x}: already patched, skipping")
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
