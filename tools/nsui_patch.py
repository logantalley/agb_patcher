#!/usr/bin/env python3
"""
nsui_patch.py - NSUI-compatible GBA sleep patch for 3DS Virtual Console

Replicates the patching strategy used by NSUI (New Super Ultimate Injector):
- Patch 1: ARM sleep entry — replaces BX r1 with STR r0,[r1] to use hardware
            REG_HALTCNT sleep, which the 3DS wakes from automatically on lid open
- Patch 2: ARM wake pointer — replaces ROM function pointer with 0x03007FFC
            (GBA interrupt vector) so wake is driven by hardware interrupt
- Patch 3: Thumb wake check — NOPs out the BX r0 to skip button polling
- Patch 4: ARM wake pointer (second instance) — same as Patch 2

Unlike gba-sleephack-patcher-tool which injects a 504-byte software wake handler
and polls for a button combo, this patch uses the GBA hardware interrupt system
so the game resumes automatically when the 3DS lid is opened.

Usage:
    python3 nsui_patch.py input.gba output.gba
    python3 nsui_patch.py input.gba output.gba --dry-run
"""

import sys
import struct
import argparse

INTERRUPT_VECTOR = b'\xfc\x7f\x00\x03'  # 0x03007FFC — GBA IWRAM interrupt handler

def apply_nsui_sleep_patch(rom_bytes, verbose=False):
    """
    Apply NSUI-compatible sleep patch to a GBA ROM.

    Returns (patched_bytes, patch_list) on success,
    or raises ValueError with a descriptive message on failure.
    """
    data = bytearray(rom_bytes)
    patches = []

    def log(msg):
        if verbose:
            print(f"  {msg}")

    # ------------------------------------------------------------------
    # PATCH 1: ARM sleep entry
    # Scan for: ADD r0, pc, #N  (XX 00 8f e2)
    #           BX r1           (11 ff 2f e1)
    # Replace BX r1 with: STR r0, [r1]  (00 00 81 e5)
    #
    # r1 holds REG_HALTCNT (0x04000301). STR writes directly to it,
    # triggering hardware sleep that the 3DS wakes from on lid open.
    # ------------------------------------------------------------------
    p1_offset = None
    for i in range(0, len(data) - 8, 4):
        if (data[i+1] == 0x00 and data[i+2] == 0x8f and data[i+3] == 0xe2 and
                data[i+4] == 0x11 and data[i+5] == 0xff and
                data[i+6] == 0x2f and data[i+7] == 0xe1):
            p1_offset = i + 4
            data[p1_offset:p1_offset+4] = b'\x00\x00\x81\xe5'
            patches.append(('P1_sleep_entry', p1_offset))
            log(f"P1 @ 0x{p1_offset:08x}: BX r1 -> STR r0,[r1]")
            break

    if p1_offset is None:
        raise ValueError(
            "P1 not found: ADD r0,pc,#N + BX r1 pattern missing. "
            "ROM may already be patched or use an unsupported sleep routine.")

    # ------------------------------------------------------------------
    # PATCH 2: ARM wake pointer (near sleep entry)
    # Scan forward from P1 for a ROM pointer in the 0x09Exxxxx-0x09Fxxxxx
    # range — these point to the injected sleep handler at end of ROM.
    # Replace with 0x03007FFC (interrupt vector).
    # ------------------------------------------------------------------
    p2_found = False
    for j in range(p1_offset + 4, p1_offset + 0x300, 4):
        val = struct.unpack('<I', bytes(data[j:j+4]))[0]
        if 0x09E00000 <= val <= 0x09FFFFFF:
            log(f"P2 @ 0x{j:08x}: ROM ptr 0x{val:08x} -> 0x03007FFC")
            data[j:j+4] = INTERRUPT_VECTOR
            patches.append(('P2_wake_ptr', j))
            p2_found = True
            break

    if not p2_found:
        raise ValueError(
            "P2 not found: no high-ROM pointer found after P1. "
            "ROM may already be patched or the sleep routine structure differs.")

    # ------------------------------------------------------------------
    # PATCH 3: Thumb wake check NOP
    # Scan for exact sequence:
    #   d0 f0 90 fd  — Thumb BL (call to sleep function)
    #   06 48        — LDR r0, [pc, #N]
    #   00 47        — BX r0 (branch to wake handler)
    # Replace 00 47 with 04 60 (MOV r0, r0 — Thumb NOP)
    # ------------------------------------------------------------------
    pattern3 = bytes([0xd0, 0xf0, 0x90, 0xfd, 0x06, 0x48, 0x00, 0x47])
    p3_idx = bytes(data).find(pattern3)
    if p3_idx == -1:
        raise ValueError(
            "P3 not found: Thumb BL + LDR + BX r0 pattern missing. "
            "ROM may already be patched or use a different Thumb wake check.")
    p3_offset = p3_idx + 6
    data[p3_offset:p3_offset+2] = b'\x04\x60'
    patches.append(('P3_thumb_nop', p3_offset))
    log(f"P3 @ 0x{p3_offset:08x}: BX r0 -> MOV r0,r0 (NOP)")

    # ------------------------------------------------------------------
    # PATCH 4: ARM wake pointer (near Thumb section)
    # Scan forward from P3 for second high-ROM pointer.
    # Replace with 0x03007FFC.
    # ------------------------------------------------------------------
    p4_found = False
    for j in range(p3_idx + 4, p3_idx + 0x40, 4):
        val = struct.unpack('<I', bytes(data[j:j+4]))[0]
        if 0x09E00000 <= val <= 0x09FFFFFF:
            log(f"P4 @ 0x{j:08x}: ROM ptr 0x{val:08x} -> 0x03007FFC")
            data[j:j+4] = INTERRUPT_VECTOR
            patches.append(('P4_wake_ptr', j))
            p4_found = True
            break

    if not p4_found:
        raise ValueError(
            "P4 not found: no high-ROM pointer found near Thumb section. "
            "ROM may already be patched or the data table structure differs.")

    return bytes(data), patches


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
        patched, patches = apply_nsui_sleep_patch(rom, verbose=args.verbose or args.dry_run)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    names = [n for n, _ in patches]
    offsets = {n: hex(o) for n, o in patches}
    print(f"Patches: {', '.join(f'{n}@{offsets[n]}' for n, _ in patches)}")

    if args.dry_run:
        print("Dry run — no output written.")
        return

    with open(args.output, 'wb') as f:
        f.write(patched)
    print(f"Output: {args.output}")


if __name__ == '__main__':
    main()
