"""
BYOVD Scanner - Vulnerable Driver Discovery Tool

Scans Windows drivers for exploitable IOCTL primitives:
- Physical memory read/write (MmMapIoSpace)
- MSR read/write (__readmsr/__writemsr)
- Port I/O (in/out instructions)
- PCI config access
- CR register access
"""

__version__ = "0.1.0"

from .scanner import DriverScanner, DriverInfo, Capability
from .patterns import DANGEROUS_IMPORTS, KNOWN_VULN_IOCTLS

__all__ = [
    "DriverScanner",
    "DriverInfo",
    "Capability",
    "DANGEROUS_IMPORTS",
    "KNOWN_VULN_IOCTLS",
]
