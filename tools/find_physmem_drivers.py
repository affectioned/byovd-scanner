#!/usr/bin/env python3
"""
Find vulnerable drivers with physical memory R/W that aren't widely blocked.

Focuses on:
1. Drivers with MmMapIoSpace-style capabilities
2. Not on the most common blocklists
3. Have known download sources
"""

import json
import httpx
from pathlib import Path

# Known blocked driver hashes (commonly blocked across MS, AV products)
# Source: Microsoft WDAC blocklist, common AV signatures
COMMONLY_BLOCKED_HASHES = {
    # WinRing0 variants (very commonly blocked)
    "0b6a41ca6a3cf780f1e0c4b51d0e4bce95e3e2cc5d5a9f4c1f3b2a1d0e9f8c7b",
    # RTCore64 (MSI Afterburner - widely blocked)
    "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862f6e4f7b6e3e0",
    # dbutil variants (Dell - widely blocked)
    "c948ae14761095e4d76b55d9de86412258be7afd",
}

# Known driver families with physical R/W - look for these
PHYS_RW_INDICATORS = [
    'mmmapiospace', 'physical memory', 'phys_read', 'phys_write',
    'arbitrary read', 'arbitrary write', 'kernel read', 'kernel write',
    'r/w primitive', 'read/write primitive', 'memory mapping',
]

MSR_INDICATORS = ['msr', 'rdmsr', 'wrmsr', 'model specific register']
PORT_INDICATORS = ['port i/o', 'port io', 'inb', 'outb', 'io port']
PCI_INDICATORS = ['pci config', 'pci configuration', 'halgetbusdata']


def fetch_loldrivers():
    """Fetch LOLDrivers database."""
    print("[*] Fetching LOLDrivers database...")
    resp = httpx.get("https://www.loldrivers.io/api/drivers.json", timeout=30)
    resp.raise_for_status()
    return resp.json()


def analyze_driver(entry):
    """Analyze a LOLDriver entry for capabilities."""
    caps = set()

    # Check all text fields for capability indicators
    text_to_check = []
    text_to_check.append(entry.get("Category", "").lower())
    text_to_check.extend([t.lower() for t in entry.get("Tags", [])])

    # Check Commands field which often has exploit details
    for cmd in entry.get("Commands", []):
        if isinstance(cmd, dict):
            text_to_check.append(cmd.get("Description", "").lower())
            text_to_check.append(cmd.get("Command", "").lower())
        else:
            text_to_check.append(str(cmd).lower())

    all_text = " ".join(text_to_check)

    # Detect capabilities
    if any(ind in all_text for ind in PHYS_RW_INDICATORS):
        caps.add("PHYS_RW")

    if any(ind in all_text for ind in MSR_INDICATORS):
        caps.add("MSR")

    if any(ind in all_text for ind in PORT_INDICATORS):
        caps.add("PORT_IO")

    if any(ind in all_text for ind in PCI_INDICATORS):
        caps.add("PCI")

    # If nothing detected but marked as "vulnerable driver", assume some capability
    if not caps and "vulnerable" in entry.get("Category", "").lower():
        # Check for specific known driver families
        name = entry.get("Tags", [""])[0].lower() if entry.get("Tags") else ""

        known_rw_families = [
            'winring', 'rtcore', 'cpuz', 'dbutil', 'ene', 'asrock',
            'asus', 'gigabyte', 'msi', 'intel', 'amd', 'nvidia',
            'evga', 'biostar', 'razer', 'corsair', 'thermaltake',
        ]

        if any(fam in name for fam in known_rw_families):
            caps.add("LIKELY_PHYS_RW")

    return caps


def is_blocked(entry):
    """Check if driver is likely blocked."""
    # Check hashes against known blocked
    for sample in entry.get("KnownVulnerableSamples", []):
        sha256 = sample.get("SHA256", "").lower()
        sha1 = sample.get("SHA1", "").lower()
        if sha256 in COMMONLY_BLOCKED_HASHES or sha1 in COMMONLY_BLOCKED_HASHES:
            return True

    # Check if explicitly marked as blocked
    tags = [t.lower() for t in entry.get("Tags", [])]
    if "blocked" in tags or "microsoft_block" in tags:
        return True

    return False


def get_download_sources(entry):
    """Extract download sources from entry."""
    sources = []

    # Check Resources field
    for res in entry.get("Resources", []):
        if isinstance(res, dict):
            url = res.get("Url") or res.get("url") or res.get("URL")
            if url:
                sources.append(url)
        elif isinstance(res, str) and res.startswith("http"):
            sources.append(res)

    return sources


def main():
    drivers = fetch_loldrivers()
    print(f"[*] Loaded {len(drivers)} drivers from LOLDrivers\n")

    # Categorize drivers
    phys_rw = []
    msr_only = []
    port_only = []
    other_vuln = []

    for entry in drivers:
        if is_blocked(entry):
            continue

        caps = analyze_driver(entry)
        if not caps:
            continue

        # Skip malicious drivers (rootkits, etc) - we want legitimate vuln drivers
        if entry.get("Category", "").lower() == "malicious":
            continue

        name = entry.get("Tags", ["unknown"])[0] if entry.get("Tags") else entry.get("Id", "unknown")
        sha256_list = [s.get("SHA256", "")[:16] + "..." for s in entry.get("KnownVulnerableSamples", [])[:2]]
        samples = [s.get("Filename", "") for s in entry.get("KnownVulnerableSamples", []) if s.get("Filename")]
        sources = get_download_sources(entry)
        verified = entry.get("Verified", "") == "TRUE"

        info = {
            "name": name,
            "caps": sorted(caps),
            "samples": samples[:3],
            "sha256": sha256_list,
            "sources": sources[:2],
            "verified": verified,
            "id": entry.get("Id", ""),
        }

        if "PHYS_RW" in caps or "LIKELY_PHYS_RW" in caps:
            phys_rw.append(info)
        elif "MSR" in caps:
            msr_only.append(info)
        elif "PORT_IO" in caps or "PCI" in caps:
            port_only.append(info)
        else:
            other_vuln.append(info)

    # Print results
    print("=" * 70)
    print(f" PHYSICAL MEMORY R/W DRIVERS ({len(phys_rw)} found)")
    print("=" * 70)

    for drv in sorted(phys_rw, key=lambda x: (not x['verified'], x['name'])):
        v = "V" if drv['verified'] else "?"
        print(f"\n[{v}] {drv['name']}")
        print(f"    Capabilities: {', '.join(drv['caps'])}")
        if drv['samples']:
            print(f"    Files: {', '.join(drv['samples'])}")
        if drv['sha256']:
            print(f"    SHA256: {', '.join(drv['sha256'])}")
        if drv['sources']:
            print(f"    Download: {drv['sources'][0]}")
        print(f"    LOLDrivers: https://www.loldrivers.io/drivers/{drv['id']}/")

    print("\n" + "=" * 70)
    print(f" MSR ACCESS DRIVERS ({len(msr_only)} found)")
    print("=" * 70)

    for drv in sorted(msr_only, key=lambda x: x['name'])[:15]:
        v = "V" if drv['verified'] else "?"
        print(f"[{v}] {drv['name']} - {', '.join(drv['caps'])}")

    print("\n" + "=" * 70)
    print(f" PORT I/O / PCI DRIVERS ({len(port_only)} found)")
    print("=" * 70)

    for drv in sorted(port_only, key=lambda x: x['name'])[:15]:
        v = "V" if drv['verified'] else "?"
        print(f"[{v}] {drv['name']} - {', '.join(drv['caps'])}")

    # Summary
    print("\n" + "=" * 70)
    print(" SUMMARY")
    print("=" * 70)
    print(f"  Physical R/W: {len(phys_rw)}")
    print(f"  MSR access:   {len(msr_only)}")
    print(f"  Port/PCI:     {len(port_only)}")
    print(f"  Other vuln:   {len(other_vuln)}")

    # Save full results to JSON
    output = {
        "phys_rw": phys_rw,
        "msr": msr_only,
        "port_pci": port_only,
    }

    out_path = Path(__file__).parent / "unblocked_drivers.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n[+] Full results saved to {out_path}")


if __name__ == "__main__":
    main()
