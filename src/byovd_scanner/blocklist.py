"""
Microsoft Driver Blocklist integration.

Fetches and parses the Microsoft recommended driver block rules to filter
out drivers that Windows Defender Application Control (WDAC) will block.

Source: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules
"""

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set
import httpx


# Microsoft's blocklist - multiple sources
BLOCKLIST_URLS = [
    # Primary: Microsoft's official documentation
    "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/main/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md",
    # Backup: Different branch
    "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules",
]

# LOLDrivers also maintains a copy of blocked hashes
LOLDRIVERS_BLOCKLIST_URL = "https://www.loldrivers.io/api/drivers.json"

BLOCKLIST_CACHE = Path.home() / ".cache" / "byovd-scanner" / "ms_blocklist.json"


@dataclass
class BlockedDriver:
    """A driver on Microsoft's blocklist."""
    name: str
    sha256: Optional[str]
    sha1: Optional[str]
    original_filename: Optional[str]
    internal_name: Optional[str]
    file_description: Optional[str]
    product_name: Optional[str]
    min_version: Optional[str]
    max_version: Optional[str]


class MSBlocklist:
    """Microsoft driver blocklist database."""

    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_file = cache_dir / "ms_blocklist.json" if cache_dir else BLOCKLIST_CACHE
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        self._blocked_sha256: Set[str] = set()
        self._blocked_sha1: Set[str] = set()
        self._blocked_names: Set[str] = set()
        self._drivers: List[BlockedDriver] = []

    def load_from_cache(self) -> bool:
        """Load blocklist from local cache."""
        if not self.cache_file.exists():
            return False

        try:
            with open(self.cache_file, "r") as f:
                data = json.load(f)
            self._blocked_sha256 = set(data.get("sha256", []))
            self._blocked_sha1 = set(data.get("sha1", []))
            self._blocked_names = set(data.get("names", []))
            return True
        except Exception:
            return False

    def update(self, force: bool = False) -> bool:
        """Download and parse latest blocklist."""
        if not force and self.cache_file.exists():
            import time
            cache_age = time.time() - self.cache_file.stat().st_mtime
            if cache_age < 86400 * 7:  # 7 days
                return self.load_from_cache()

        # Try multiple sources
        content = None
        for url in BLOCKLIST_URLS:
            try:
                response = httpx.get(url, timeout=30, follow_redirects=True)
                response.raise_for_status()
                content = response.text
                print(f"[+] Fetched blocklist from {url[:50]}...")
                break
            except Exception:
                continue

        if content:
            self._parse_markdown_blocklist(content)

        # Also extract blocked hashes from LOLDrivers (they track this)
        try:
            response = httpx.get(LOLDRIVERS_BLOCKLIST_URL, timeout=30)
            response.raise_for_status()
            lol_data = response.json()
            self._extract_blocked_from_loldrivers(lol_data)
        except Exception as e:
            print(f"[!] Could not fetch LOLDrivers for blocklist info: {e}")

        # Save to cache
        cache_data = {
            "sha256": list(self._blocked_sha256),
            "sha1": list(self._blocked_sha1),
            "names": list(self._blocked_names),
        }
        with open(self.cache_file, "w") as f:
            json.dump(cache_data, f)

        return len(self._blocked_sha256) > 0 or self.load_from_cache()

    def _extract_blocked_from_loldrivers(self, data: List[Dict]):
        """Extract blocking info from LOLDrivers data."""
        for entry in data:
            # LOLDrivers tracks if driver is on MS blocklist
            # Check for blocking indicators in the entry
            category = entry.get("Category", "").lower()
            tags = [t.lower() for t in entry.get("Tags", [])]

            # If marked as blocked, add hashes
            if "blocked" in category or any("block" in t for t in tags):
                for sample in entry.get("KnownVulnerableSamples", []):
                    if sample.get("SHA256"):
                        self._blocked_sha256.add(sample["SHA256"].lower())
                    if sample.get("SHA1"):
                        self._blocked_sha1.add(sample["SHA1"].lower())

    def _parse_markdown_blocklist(self, content: str):
        """Parse blocklist from Microsoft's markdown documentation."""
        self._blocked_sha256.clear()
        self._blocked_sha1.clear()
        self._blocked_names.clear()

        # Extract SHA256 hashes (64 hex chars)
        sha256_pattern = re.compile(r'\b([a-fA-F0-9]{64})\b')
        for match in sha256_pattern.finditer(content):
            self._blocked_sha256.add(match.group(1).lower())

        # Extract SHA1 hashes (40 hex chars) - be careful not to match partial SHA256
        sha1_pattern = re.compile(r'(?<![a-fA-F0-9])([a-fA-F0-9]{40})(?![a-fA-F0-9])')
        for match in sha1_pattern.finditer(content):
            self._blocked_sha1.add(match.group(1).lower())

        # Extract driver names from XML snippets in the markdown
        # Look for OriginalFileName and InternalName in FileAttribRef
        name_patterns = [
            re.compile(r'OriginalFileName="([^"]+)"', re.IGNORECASE),
            re.compile(r'InternalName="([^"]+)"', re.IGNORECASE),
            re.compile(r'FileName="([^"]+\.sys)"', re.IGNORECASE),
        ]
        for pattern in name_patterns:
            for match in pattern.finditer(content):
                name = match.group(1).lower()
                if name.endswith('.sys'):
                    self._blocked_names.add(name)
                else:
                    self._blocked_names.add(name + '.sys')
                    self._blocked_names.add(name)

    def is_blocked(self, sha256: Optional[str] = None, sha1: Optional[str] = None,
                   name: Optional[str] = None) -> bool:
        """Check if a driver is on the blocklist."""
        if sha256 and sha256.lower() in self._blocked_sha256:
            return True
        if sha1 and sha1.lower() in self._blocked_sha1:
            return True
        if name:
            name_lower = name.lower()
            if name_lower in self._blocked_names:
                return True
            # Also check without .sys extension
            if name_lower.endswith('.sys'):
                if name_lower[:-4] in self._blocked_names:
                    return True
        return False

    @property
    def blocked_count(self) -> int:
        """Number of unique blocked hashes."""
        return len(self._blocked_sha256) + len(self._blocked_sha1)

    @property
    def blocked_sha256_hashes(self) -> Set[str]:
        return self._blocked_sha256.copy()

    @property
    def blocked_names(self) -> Set[str]:
        return self._blocked_names.copy()


def find_unblocked_loldrivers() -> List[Dict]:
    """
    Find LOLDrivers that are NOT on Microsoft's blocklist.

    Returns list of drivers with R/W capabilities that should still work.
    """
    from .loldrivers import LOLDriversDB

    # Load both databases
    blocklist = MSBlocklist()
    if not blocklist.load_from_cache():
        print("[*] Downloading Microsoft blocklist...")
        blocklist.update()

    loldb = LOLDriversDB()
    if not loldb.load_from_cache():
        print("[*] Downloading LOLDrivers database...")
        loldb.update()

    print(f"[*] Blocklist: {blocklist.blocked_count} hashes, {len(blocklist.blocked_names)} names")
    print(f"[*] LOLDrivers: {loldb.count} drivers")

    unblocked = []

    for driver in loldb.get_all():
        # Check if any hash is blocked
        is_blocked = False

        for sha256 in driver.sha256_hashes:
            if blocklist.is_blocked(sha256=sha256):
                is_blocked = True
                break

        for sha1 in driver.sha1_hashes:
            if blocklist.is_blocked(sha1=sha1):
                is_blocked = True
                break

        # Check name
        for sample_name in driver.known_vuln_samples:
            if blocklist.is_blocked(name=sample_name):
                is_blocked = True
                break

        if blocklist.is_blocked(name=driver.name):
            is_blocked = True

        if not is_blocked:
            # Determine capabilities from tags/category
            caps = []
            tags_lower = [t.lower() for t in driver.tags]
            cat_lower = driver.category.lower()

            if any(x in tags_lower or x in cat_lower for x in ['memory', 'physical', 'mmmapiospace']):
                caps.append('PHYS_RW')
            if any(x in tags_lower or x in cat_lower for x in ['msr', 'rdmsr', 'wrmsr']):
                caps.append('MSR')
            if any(x in tags_lower or x in cat_lower for x in ['port', 'i/o', 'io']):
                caps.append('PORT_IO')
            if any(x in tags_lower or x in cat_lower for x in ['pci']):
                caps.append('PCI')

            # Extract resource URLs safely
            resources = []
            for r in driver.resources[:2]:
                if isinstance(r, dict):
                    resources.append(r.get('url', r.get('URL', str(r))))
                else:
                    resources.append(str(r))

            unblocked.append({
                'id': driver.id,
                'name': driver.name,
                'category': driver.category,
                'verified': driver.verified,
                'tags': driver.tags,
                'capabilities': caps or ['UNKNOWN'],
                'sha256': driver.sha256_hashes[:3],  # First 3 hashes
                'samples': driver.known_vuln_samples[:3],
                'resources': resources,
            })

    return unblocked


if __name__ == "__main__":
    # Quick test
    print("Finding unblocked vulnerable drivers...")
    results = find_unblocked_loldrivers()

    print(f"\n{'='*60}")
    print(f"Found {len(results)} potentially unblocked drivers")
    print(f"{'='*60}\n")

    # Sort by whether they have known capabilities
    results.sort(key=lambda x: (0 if 'PHYS_RW' in x['capabilities'] else 1, x['name']))

    for drv in results[:30]:
        caps = ', '.join(drv['capabilities'])
        print(f"[{'V' if drv['verified'] else '?'}] {drv['name']}")
        print(f"    Category: {drv['category']}")
        print(f"    Caps: {caps}")
        if drv['samples']:
            print(f"    Samples: {', '.join(drv['samples'][:2])}")
        print()
