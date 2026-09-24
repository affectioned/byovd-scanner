"""
Core driver scanning functionality.
"""

import hashlib
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pefile

from .patterns import (
    DANGEROUS_IMPORTS,
    INTRINSIC_PATTERNS,
    KNOWN_VULN_IOCTLS,
    Capability,
)


@dataclass
class DriverInfo:
    """Information about a scanned driver."""

    path: str
    name: str
    sha256: str
    size: int
    signed: bool
    signer: Optional[str]
    capabilities: Capability
    imports: List[str]
    intrinsics: List[Tuple[int, str]]
    known_ioctls: List[Tuple[int, str]]
    candidate_ioctls: List[int]
    device_names: List[str]
    version: Optional[str]
    description: Optional[str]
    company: Optional[str] = None
    product: Optional[str] = None

    @property
    def has_read(self) -> bool:
        return bool(
            self.capabilities
            & (
                Capability.PHYS_READ
                | Capability.MSR_READ
                | Capability.PORT_READ
                | Capability.PCI_READ
                | Capability.CR_READ
            )
        )

    @property
    def has_write(self) -> bool:
        return bool(
            self.capabilities
            & (
                Capability.PHYS_WRITE
                | Capability.MSR_WRITE
                | Capability.PORT_WRITE
                | Capability.PCI_WRITE
                | Capability.CR_WRITE
            )
        )

    @property
    def capability_class(self) -> str:
        if self.has_read and self.has_write:
            return "READ_WRITE"
        elif self.has_read:
            return "READ_ONLY"
        elif self.has_write:
            return "WRITE_ONLY"
        return "NONE"

    @property
    def is_vulnerable(self) -> bool:
        return self.capability_class != "NONE"

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "name": self.name,
            "sha256": self.sha256,
            "size": self.size,
            "signed": self.signed,
            "signer": self.signer,
            "capabilities": str(self.capabilities),
            "capability_class": self.capability_class,
            "imports": self.imports,
            "intrinsics": [{"offset": hex(o), "insn": i} for o, i in self.intrinsics],
            "known_ioctls": [{"code": hex(c), "desc": d} for c, d in self.known_ioctls],
            "candidate_ioctls": [hex(i) for i in self.candidate_ioctls],
            "device_names": self.device_names,
            "version": self.version,
            "description": self.description,
            "company": self.company,
            "product": self.product,
        }


class DriverScanner:
    """Scanner for analyzing Windows drivers for vulnerable IOCTL patterns."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def scan_file(self, path: str | Path) -> Optional[DriverInfo]:
        """Scan a single driver file."""
        path = Path(path)
        if not path.exists():
            return None

        try:
            pe = pefile.PE(str(path), fast_load=False)
        except Exception as e:
            if self.verbose:
                print(f"[-] Failed to parse {path}: {e}")
            return None

        return self._analyze_pe(pe, path)

    def scan_directory(self, directory: str | Path) -> List[DriverInfo]:
        """Scan all .sys files in a directory."""
        directory = Path(directory)
        results = []

        for sys_file in directory.rglob("*.sys"):
            info = self.scan_file(sys_file)
            if info:
                results.append(info)

        # Sort by capability (most useful first)
        cap_order = {"READ_WRITE": 0, "WRITE_ONLY": 1, "READ_ONLY": 2, "NONE": 3}
        results.sort(key=lambda x: (cap_order.get(x.capability_class, 4), -len(x.imports)))

        return results

    def _analyze_pe(self, pe: pefile.PE, path: Path) -> DriverInfo:
        """Perform full analysis on a PE file."""
        name = path.name
        sha256 = self._get_file_hash(path)
        size = path.stat().st_size
        signed, signer = self._check_signature(pe)
        version, description, company, product = self._extract_version_info(pe)

        # Analyze imports
        capabilities = Capability.NONE
        dangerous_imports = []

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        imp_name = imp.name.decode("utf-8", errors="ignore")
                        if imp_name in DANGEROUS_IMPORTS:
                            dangerous_imports.append(imp_name)
                            capabilities |= DANGEROUS_IMPORTS[imp_name]

        # Get raw data for pattern scanning
        raw_data = pe.get_memory_mapped_image()

        # Find text section info
        text_offset = 0
        text_va = 0
        for section in pe.sections:
            if b".text" in section.Name:
                text_offset = section.PointerToRawData
                text_va = section.VirtualAddress
                break

        # Scan for intrinsic instructions
        intrinsics = self._scan_intrinsics(raw_data, text_offset, text_va)
        for _, insn in intrinsics:
            for pattern, (name, cap) in INTRINSIC_PATTERNS.items():
                if name == insn:
                    capabilities |= cap
                    break

        # Extract device names
        device_names = self._find_device_names(raw_data)

        # Find IOCTL codes
        candidate_ioctls = self._find_ioctl_codes(raw_data)

        # Match against known vulnerable IOCTLs
        known_ioctls = []
        for ioctl in candidate_ioctls:
            if ioctl in KNOWN_VULN_IOCTLS:
                known_ioctls.append((ioctl, KNOWN_VULN_IOCTLS[ioctl]))

        return DriverInfo(
            path=str(path),
            name=name,
            sha256=sha256,
            size=size,
            signed=signed,
            signer=signer,
            capabilities=capabilities,
            imports=dangerous_imports,
            intrinsics=intrinsics,
            known_ioctls=known_ioctls,
            candidate_ioctls=candidate_ioctls,
            device_names=device_names,
            version=version,
            description=description,
            company=company,
            product=product,
        )

    @staticmethod
    def _get_file_hash(path: Path) -> str:
        """Calculate SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def _check_signature(pe: pefile.PE) -> Tuple[bool, Optional[str]]:
        """Check if driver has embedded signature."""
        try:
            if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
                cert_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # CERTIFICATE_TABLE
                if cert_dir.VirtualAddress != 0 and cert_dir.Size != 0:
                    return True, "(embedded signature)"
            return False, None
        except Exception:
            return False, None

    @staticmethod
    def _extract_version_info(
        pe: pefile.PE,
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """Extract version info from PE resources."""
        version = None
        description = None
        company = None
        product = None

        try:
            if hasattr(pe, "FileInfo"):
                for fi in pe.FileInfo:
                    for entry in fi:
                        if hasattr(entry, "StringTable"):
                            for st in entry.StringTable:
                                for key, value in st.entries.items():
                                    key_str = (
                                        key.decode("utf-8", errors="ignore")
                                        if isinstance(key, bytes)
                                        else key
                                    )
                                    val_str = (
                                        value.decode("utf-8", errors="ignore")
                                        if isinstance(value, bytes)
                                        else value
                                    )
                                    if key_str == "FileVersion":
                                        version = val_str
                                    elif key_str == "FileDescription":
                                        description = val_str
                                    elif key_str == "CompanyName":
                                        company = val_str
                                    elif key_str == "ProductName":
                                        product = val_str
        except Exception:
            pass

        return version, description, company, product

    @staticmethod
    def _find_device_names(data: bytes) -> List[str]:
        """Extract potential device names from binary."""
        device_names = []
        patterns = [
            b"\\Device\\",
            b"\\DosDevices\\",
            b"\\\\.\\",
            b"\\??\\",
        ]

        # ASCII search
        for pattern in patterns:
            idx = 0
            while True:
                idx = data.find(pattern, idx)
                if idx == -1:
                    break
                end = idx
                while end < len(data) and end < idx + 256:
                    if data[end : end + 1] == b"\x00":
                        break
                    end += 1
                try:
                    name = data[idx:end].decode("ascii", errors="ignore")
                    if len(name) > 8 and name not in device_names:
                        device_names.append(name)
                except Exception:
                    pass
                idx += 1

        # Wide string search
        for pattern in patterns:
            wide_pattern = pattern.decode("ascii").encode("utf-16-le")
            idx = 0
            while True:
                idx = data.find(wide_pattern, idx)
                if idx == -1:
                    break
                end = idx
                while end < len(data) - 1 and end < idx + 512:
                    if data[end : end + 2] == b"\x00\x00":
                        break
                    end += 2
                try:
                    name = data[idx:end].decode("utf-16-le", errors="ignore")
                    if len(name) > 4 and name not in device_names:
                        device_names.append(name)
                except Exception:
                    pass
                idx += 2

        return device_names

    @staticmethod
    def _find_ioctl_codes(data: bytes) -> List[int]:
        """Extract potential IOCTL codes from binary."""
        ioctls = set()

        # Common device types for vulnerable drivers
        vuln_device_types = {
            0x22,  # FILE_DEVICE_UNKNOWN
            0x80,
            0x81,
            0x82,
            0x83,
            0x9C40,
            0x9C41,
            0x9C42,
            0xC350,
            0xC351,
            0x8086,  # Intel
            0x8111,
            0x8112,  # AMD
        }

        for i in range(0, len(data) - 4, 4):
            val = struct.unpack("<I", data[i : i + 4])[0]

            device_type = (val >> 16) & 0xFFFF
            function = (val >> 2) & 0xFFF

            # Filter for vulnerable device types
            if device_type in vuln_device_types:
                if 0 < function < 0xFFF:
                    ioctls.add(val)

            # Custom device types (0x8000+)
            if 0x8000 <= device_type <= 0xFFFF:
                if 0 < function < 0xFFF:
                    ioctls.add(val)

        return sorted(ioctls)

    @staticmethod
    def _scan_intrinsics(
        data: bytes, text_offset: int, text_va: int
    ) -> List[Tuple[int, str]]:
        """Scan for dangerous intrinsic instructions."""
        found = []

        for pattern, (name, _) in INTRINSIC_PATTERNS.items():
            idx = 0
            while True:
                idx = data.find(pattern, idx)
                if idx == -1:
                    break

                # Calculate RVA
                if text_offset <= idx < text_offset + len(data):
                    rva = text_va + (idx - text_offset)
                else:
                    rva = idx

                found.append((rva, name))
                idx += 1

        return found
