"""
Vulnerability patterns and signatures for driver analysis.
"""

from enum import Flag, auto
from typing import Dict, Tuple


class Capability(Flag):
    """Driver exploitation capabilities."""
    NONE = 0
    PHYS_READ = auto()
    PHYS_WRITE = auto()
    MSR_READ = auto()
    MSR_WRITE = auto()
    PORT_READ = auto()
    PORT_WRITE = auto()
    PCI_READ = auto()
    PCI_WRITE = auto()
    CR_READ = auto()
    CR_WRITE = auto()
    VIRT_TO_PHYS = auto()
    ALLOC_CONTIGUOUS = auto()
    MAP_MEMORY = auto()


# Import patterns that indicate dangerous functionality
DANGEROUS_IMPORTS: Dict[str, Capability] = {
    # Physical memory mapping
    "MmMapIoSpace": Capability.PHYS_READ | Capability.PHYS_WRITE,
    "MmMapIoSpaceEx": Capability.PHYS_READ | Capability.PHYS_WRITE,
    "MmUnmapIoSpace": Capability.PHYS_READ | Capability.PHYS_WRITE,
    "MmGetPhysicalAddress": Capability.VIRT_TO_PHYS,
    "MmAllocateContiguousMemory": Capability.ALLOC_CONTIGUOUS,
    "MmAllocateContiguousMemorySpecifyCache": Capability.ALLOC_CONTIGUOUS,
    "MmAllocateContiguousMemorySpecifyCacheNode": Capability.ALLOC_CONTIGUOUS,

    # Section/MDL mapping
    "ZwMapViewOfSection": Capability.MAP_MEMORY,
    "ZwOpenSection": Capability.MAP_MEMORY,
    "MmMapLockedPages": Capability.MAP_MEMORY,
    "MmMapLockedPagesSpecifyCache": Capability.MAP_MEMORY,

    # Port I/O - HAL exports
    "READ_PORT_UCHAR": Capability.PORT_READ,
    "READ_PORT_USHORT": Capability.PORT_READ,
    "READ_PORT_ULONG": Capability.PORT_READ,
    "READ_PORT_BUFFER_UCHAR": Capability.PORT_READ,
    "READ_PORT_BUFFER_USHORT": Capability.PORT_READ,
    "READ_PORT_BUFFER_ULONG": Capability.PORT_READ,
    "WRITE_PORT_UCHAR": Capability.PORT_WRITE,
    "WRITE_PORT_USHORT": Capability.PORT_WRITE,
    "WRITE_PORT_ULONG": Capability.PORT_WRITE,
    "WRITE_PORT_BUFFER_UCHAR": Capability.PORT_WRITE,
    "WRITE_PORT_BUFFER_USHORT": Capability.PORT_WRITE,
    "WRITE_PORT_BUFFER_ULONG": Capability.PORT_WRITE,

    # PCI config space
    "HalGetBusData": Capability.PCI_READ,
    "HalGetBusDataByOffset": Capability.PCI_READ,
    "HalSetBusData": Capability.PCI_WRITE,
    "HalSetBusDataByOffset": Capability.PCI_WRITE,

    # Rarely exported but sometimes present
    "HalTranslateBusAddress": Capability.VIRT_TO_PHYS,
}

# Inline intrinsic patterns (x64 opcodes)
INTRINSIC_PATTERNS: Dict[bytes, Tuple[str, Capability]] = {
    # rdmsr: 0F 32
    bytes.fromhex("0f32"): ("rdmsr", Capability.MSR_READ),
    # wrmsr: 0F 30
    bytes.fromhex("0f30"): ("wrmsr", Capability.MSR_WRITE),
    # in al, dx: EC
    bytes.fromhex("ec"): ("in al,dx", Capability.PORT_READ),
    # in ax, dx: 66 ED
    bytes.fromhex("66ed"): ("in ax,dx", Capability.PORT_READ),
    # in eax, dx: ED
    bytes.fromhex("ed"): ("in eax,dx", Capability.PORT_READ),
    # out dx, al: EE
    bytes.fromhex("ee"): ("out dx,al", Capability.PORT_WRITE),
    # out dx, ax: 66 EF
    bytes.fromhex("66ef"): ("out dx,ax", Capability.PORT_WRITE),
    # out dx, eax: EF
    bytes.fromhex("ef"): ("out dx,eax", Capability.PORT_WRITE),
    # mov rax, cr0: 0F 20 C0
    bytes.fromhex("0f20c0"): ("mov rax,cr0", Capability.CR_READ),
    # mov rax, cr2: 0F 20 D0
    bytes.fromhex("0f20d0"): ("mov rax,cr2", Capability.CR_READ),
    # mov rax, cr3: 0F 20 D8
    bytes.fromhex("0f20d8"): ("mov rax,cr3", Capability.CR_READ),
    # mov rax, cr4: 0F 20 E0
    bytes.fromhex("0f20e0"): ("mov rax,cr4", Capability.CR_READ),
    # mov cr0, rax: 0F 22 C0
    bytes.fromhex("0f22c0"): ("mov cr0,rax", Capability.CR_WRITE),
    # mov cr3, rax: 0F 22 D8
    bytes.fromhex("0f22d8"): ("mov cr3,rax", Capability.CR_WRITE),
    # mov cr4, rax: 0F 22 E0
    bytes.fromhex("0f22e0"): ("mov cr4,rax", Capability.CR_WRITE),
    # cpuid: 0F A2 (not dangerous but informative)
    bytes.fromhex("0fa2"): ("cpuid", Capability.NONE),
    # invd: 0F 08 (cache invalidate - dangerous)
    bytes.fromhex("0f08"): ("invd", Capability.NONE),
    # wbinvd: 0F 09 (write-back and invalidate)
    bytes.fromhex("0f09"): ("wbinvd", Capability.NONE),
}

# Known vulnerable IOCTL codes from public research
# Source: LOLDrivers, VDM research, public exploits
KNOWN_VULN_IOCTLS: Dict[int, str] = {
    # Dell/Alienware DBUtil family
    0x9C402400: "Dell physical read (dword)",
    0x9C402404: "Dell physical read (word)",
    0x9C402408: "Dell physical read (byte)",
    0x9C40240C: "Dell physical write (dword)",
    0x9C402410: "Dell physical write (word)",
    0x9C402414: "Dell physical write (byte)",

    # WDT Kernel (Dell Watchdog Timer)
    0x9C412400: "WDT physical read (dword)",
    0x9C412404: "WDT physical read (word)",
    0x9C412408: "WDT physical read (byte)",
    0x9C41240C: "WDT physical write (dword)",
    0x9C412410: "WDT physical write (word)",
    0x9C412414: "WDT physical write (byte)",

    # Intel HECI/MEI
    0x80862007: "Intel HECI read",
    0x80862008: "Intel HECI write",

    # WinRing0/WinIo family (very common)
    0x9C402084: "WinRing0 map physical",
    0x9C402088: "WinRing0 unmap physical",
    0x9C40208C: "WinRing0 read port byte",
    0x9C402090: "WinRing0 write port byte",
    0x9C402094: "WinRing0 read msr",
    0x9C402098: "WinRing0 write msr",
    0x9C40209C: "WinRing0 read pci config",
    0x9C4020A0: "WinRing0 write pci config",
    0x9C4020A4: "WinRing0 read memory",
    0x9C4020A8: "WinRing0 write memory",

    # RTCore64 (MSI Afterburner)
    0x80002000: "RTCore64 read memory",
    0x80002004: "RTCore64 write memory",
    0x80002008: "RTCore64 read pci config",
    0x8000200C: "RTCore64 write pci config",

    # CPUZ
    0x9C402428: "CPUZ read physical",
    0x9C40242C: "CPUZ write physical",
    0x9C402430: "CPUZ read control register",
    0x9C402434: "CPUZ read msr",
    0x9C402438: "CPUZ write msr",

    # ASUS
    0x0022200C: "ASUS read physical",
    0x00222010: "ASUS write physical",
    0x00222014: "ASUS map physical",

    # Gigabyte
    0xC3502004: "Gigabyte read physical",
    0xC3502008: "Gigabyte write physical",
    0xC350200C: "Gigabyte read msr",
    0xC3502010: "Gigabyte write msr",

    # EVGA Precision
    0x80002040: "EVGA read physical",
    0x80002044: "EVGA write physical",

    # AMD Ryzen Master
    0x81112030: "AMD read msr",
    0x81112034: "AMD write msr",
    0x81112038: "AMD read pci config",
    0x8111203C: "AMD write pci config",

    # Generic/Common patterns
    0x9C406000: "Generic physical map",
    0x9C406004: "Generic physical unmap",
    0x9C406008: "Generic read memory",
    0x9C40600C: "Generic write memory",

    # Intel Network Adapter Diagnostic
    0x80862000: "Intel NIC read physical",
    0x80862004: "Intel NIC write physical",

    # Razer
    0x22240C: "Razer read physical",
    0x222410: "Razer write physical",

    # Biostar
    0x226004: "Biostar read physical",
    0x226008: "Biostar write physical",

    # AsRock
    0x222808: "AsRock read physical",
    0x22280C: "AsRock write physical",

    # Zemana
    0x80002010: "Zemana read physical",
    0x80002014: "Zemana write physical",

    # Process Hacker/KProcessHacker
    0x999201: "KPH read memory",
    0x999205: "KPH write memory",
    0x999209: "KPH open process",
}

# YARA rule for comprehensive driver scanning
YARA_RULES = """
rule VulnerableDriver_MmMapIoSpace {
    meta:
        description = "Driver imports MmMapIoSpace for physical memory access"
        severity = "high"
    strings:
        $import1 = "MmMapIoSpace" ascii wide
        $import2 = "MmMapIoSpaceEx" ascii wide
    condition:
        uint16(0) == 0x5A4D and (any of ($import*))
}

rule VulnerableDriver_MSR {
    meta:
        description = "Driver contains MSR read/write instructions"
        severity = "high"
    strings:
        $rdmsr = { 0F 32 }
        $wrmsr = { 0F 30 }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule VulnerableDriver_PortIO {
    meta:
        description = "Driver contains port I/O instructions"
        severity = "medium"
    strings:
        $in_al = { EC }
        $in_ax = { 66 ED }
        $in_eax = { ED }
        $out_al = { EE }
        $out_ax = { 66 EF }
        $out_eax = { EF }
    condition:
        uint16(0) == 0x5A4D and (2 of them)
}

rule VulnerableDriver_CRAccess {
    meta:
        description = "Driver contains control register access"
        severity = "high"
    strings:
        $mov_cr0_read = { 0F 20 C0 }
        $mov_cr3_read = { 0F 20 D8 }
        $mov_cr4_read = { 0F 20 E0 }
        $mov_cr0_write = { 0F 22 C0 }
        $mov_cr3_write = { 0F 22 D8 }
        $mov_cr4_write = { 0F 22 E0 }
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule VulnerableDriver_WinRing0 {
    meta:
        description = "WinRing0 family driver signature"
        severity = "critical"
    strings:
        $s1 = "WinRing0" ascii wide nocase
        $s2 = "\\\\.\\WinRing0" ascii wide
        $s3 = "\\Device\\WinRing0" ascii wide
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule VulnerableDriver_RTCore {
    meta:
        description = "RTCore64 (MSI Afterburner) driver"
        severity = "critical"
    strings:
        $s1 = "RTCore" ascii wide nocase
        $s2 = "\\\\.\\RTCore" ascii wide
        $s3 = "\\Device\\RTCore" ascii wide
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule VulnerableDriver_PhysicalMemory {
    meta:
        description = "Driver accesses \\Device\\PhysicalMemory"
        severity = "critical"
    strings:
        $s1 = "\\Device\\PhysicalMemory" ascii wide
        $s2 = "PhysicalMemory" ascii wide
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule VulnerableDriver_HalBusData {
    meta:
        description = "Driver uses HAL PCI config functions"
        severity = "medium"
    strings:
        $s1 = "HalGetBusData" ascii wide
        $s2 = "HalSetBusData" ascii wide
        $s3 = "HalGetBusDataByOffset" ascii wide
        $s4 = "HalSetBusDataByOffset" ascii wide
    condition:
        uint16(0) == 0x5A4D and (any of them)
}
"""
