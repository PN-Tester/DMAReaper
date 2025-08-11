# DMAReaper - Disable Kernel DMA Protection via pre-boot DMA attack
This program is used to control an FPGA board running the PCILeech firmware. DMAReaper will automatically seek and destroy the DMAR ACPI table on the target computer using pre-boot DMA attack. When successful, this operation will prevent usage of the IOMMU and subsequent intialization of Kernel DMA Protection when Windows Boots. This program is suitable for disabling Kernel DMA Protection when target firmware has Secure Boot, VT-d, VT-x, Sure Start, Virtualization based BIOS Security, and Enhanced Firmware runtime Intrusion and Detection Enabled.

# Usage
```
usage: DMAReaper.py [-h] [-v] [-i INTENSITY] [-min MIN_ADDR] [-max MAX_ADDR]

DMAReaper — Disable Kernel DMA Protection via DMAR overwrite

options:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbose debug output
  -i INTENSITY, --intensity INTENSITY
                        Number of times each memory segment is read during scan. Lower is faster but less reliable. (default: 3)
  -min MIN_ADDR, --min-addr MIN_ADDR
                        Minimum scan address (default: 0x52000000)
  -max MAX_ADDR, --max-addr MAX_ADDR
                        Maximum scan address (default: 0xFFFFFFFF)
```

The only value you might need to change out of the box is MIN_ADDR. You may want to put something lower than 0x52000000. Try starting at 0x30000000.

# Preparation
1. Connect the FPGA board to the target computer via appropriate PCI Express port (M.2 / ExpressCard / Mini PCIe)
2. Connect the FPGA board to the attack computer via the data port (USB-C)
3. Power on the target computer
4. Quickly power on the board to ensure proper initialization
5. Enter UEFI on the target computer
6. You may need to repeat steps 3-5 several times before you get a valid connection. Timing is key

