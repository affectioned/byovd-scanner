# BYOVD Scanner

Automated vulnerable driver discovery tool for BYOVD (Bring Your Own Vulnerable Driver) research.

Scans Windows kernel drivers (`.sys` files) for exploitable IOCTL primitives that provide:
- **Physical memory read/write** (MmMapIoSpace, MmMapIoSpaceEx)
- **MSR read/write** (__readmsr/__writemsr intrinsics)
- **Port I/O** (in/out instructions)
- **PCI config space access** (HalGetBusData*)
- **Control register access** (mov cr0/cr3/cr4)

## Features

- **Static Analysis**: PE import scanning + instruction pattern matching
- **IOCTL Detection**: Extracts and categorizes IOCTL codes from binary
- **LOLDrivers Integration**: Cross-reference with the [LOLDrivers](https://www.loldrivers.io/) database
- **IDA Pro Integration**: Deep analysis via IDA Python plugin
- **Capability Classification**: Automatic grouping by READ_WRITE / READ_ONLY / WRITE_ONLY
- **Multiple Output Formats**: Rich terminal output, JSON, CSV

## Installation

```bash
pip install byovd-scanner
```

Or from source:

```bash
git clone https://github.com/abbey/byovd-scanner.git
cd byovd-scanner
pip install -e .
```

## Usage

### Basic Scanning

```bash
# Scan a single driver
byovd-scan driver.sys

# Scan all drivers in a directory
byovd-scan C:\Windows\System32\drivers

# Scan with JSON output
byovd-scan . --json -o results.json

# Filter for READ_WRITE capability only
byovd-scan . --filter both
```

### Example Output

```
╔══════════════════════════════════════════════════════════╗
║           BYOVD Scanner - Vulnerable Driver Discovery    ║
║                  Physical R/W IOCTL Finder               ║
╚══════════════════════════════════════════════════════════╝

[*] Scanning directory: drivers/
[*] Found 3 driver(s)

┌──────────────────────────────────────────────────────────┐
│ Driver Info                                              │
├──────────────────────────────────────────────────────────┤
│ Driver: WDTKernel.sys                                    │
│ Path: drivers/WDTKernel.sys                              │
│ SHA256: abc123...                                        │
│ Size: 12,345 bytes | Signed: Yes                         │
└──────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ Capabilities                                            │
├─────────────────────────────────────────────────────────┤
│ Class: READ_WRITE                                       │
│ Raw: Capability.PHYS_READ|PHYS_WRITE                    │
└─────────────────────────────────────────────────────────┘

┏━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Dangerous Imports      ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━┩
│ MmMapIoSpace           │
│ MmUnmapIoSpace         │
└────────────────────────┘

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Known Vulnerable IOCTLs                ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 0x9C412400 │ WDT physical read (dword) │
│ 0x9C41240C │ WDT physical write (dword)│
└────────────────────────────────────────┘
```

### Python API

```python
from byovd_scanner import DriverScanner, Capability

scanner = DriverScanner()

# Scan a single driver
info = scanner.scan_file("driver.sys")
print(f"Capabilities: {info.capabilities}")
print(f"Class: {info.capability_class}")

if info.has_read and info.has_write:
    print("Found exploitable R/W driver!")
    for ioctl, desc in info.known_ioctls:
        print(f"  IOCTL 0x{ioctl:08X}: {desc}")

# Scan directory
results = scanner.scan_directory("C:/drivers")
rw_drivers = [r for r in results if r.capability_class == "READ_WRITE"]
```

### LOLDrivers Integration

```python
from byovd_scanner.loldrivers import LOLDriversDB, check_driver_against_loldrivers

# Quick check
match = check_driver_against_loldrivers(sha256="abc123...")
if match:
    print(f"Known LOLDriver: {match['name']}")

# Full database access
db = LOLDriversDB()
db.update()  # Download latest database
print(f"Database contains {db.count} drivers")

# Search
results = db.search("WinRing0")
for driver in results:
    print(f"{driver.name}: {driver.sha256_hashes}")
```

### IDA Pro Integration

Copy `src/byovd_scanner/ida_plugin.py` to IDA's plugins directory, or run directly:

```python
# In IDA Python console
exec(open("path/to/ida_plugin.py").read())

# Or import
from byovd_scanner.ida_plugin import analyze_driver
analysis = analyze_driver()
print(f"Device Control Handler: 0x{analysis.device_control_handler:X}")
```

## Capability Classes

| Class | Description | Use Case |
|-------|-------------|----------|
| `READ_WRITE` | Full physical memory R/W | Perfect for kernel exploitation |
| `READ_ONLY` | Physical memory read only | Useful for reconnaissance |
| `WRITE_ONLY` | Physical memory write only | Can corrupt but not read |
| `NONE` | No detected capabilities | May need manual analysis |

## Known IOCTL Families

The scanner recognizes IOCTL codes from:

- **Dell/Alienware** (DBUtil, WDT families)
- **Intel** (HECI/MEI, NIC diagnostic)
- **WinRing0/WinIo** (common in hardware monitoring tools)
- **RTCore64** (MSI Afterburner)
- **CPUZ** (CPU-Z diagnostic driver)
- **ASUS/ASRock/Biostar/Gigabyte** (motherboard utilities)
- **AMD Ryzen Master**
- **EVGA Precision**
- **Razer** (Synapse driver)
- **KProcessHacker**

## Adding Custom Patterns

Edit `src/byovd_scanner/patterns.py` to add:

```python
# New dangerous imports
DANGEROUS_IMPORTS["MyCustomApi"] = Capability.PHYS_READ | Capability.PHYS_WRITE

# New IOCTL codes
KNOWN_VULN_IOCTLS[0xDEADBEEF] = "My custom driver read"
```

## References

- [LOLDrivers](https://www.loldrivers.io/) - Living Off The Land Drivers database
- [VDM (Vulnerable Driver Manipulation)](https://github.com/can1357/vdm) - Original VDM research
- [KDMapper](https://github.com/TheCruZ/kdmapper) - Kernel driver mapper
- [BYOVD Attacks](https://attack.mitre.org/techniques/T1068/) - MITRE ATT&CK technique

## Legal Disclaimer

This tool is intended for authorized security research and educational purposes only. Using vulnerable drivers to bypass security controls without authorization is illegal. Always ensure you have proper authorization before conducting any security testing.

## License

MIT License - see [LICENSE](LICENSE)
