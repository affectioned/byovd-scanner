"""
LOLDrivers integration - cross-reference with known vulnerable drivers database.

LOLDrivers (Living Off The Land Drivers) is a community-driven project that
catalogs known vulnerable Windows drivers used for BYOVD attacks.

Repository: https://github.com/magicsword-io/LOLDrivers
Website: https://www.loldrivers.io/
"""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
import httpx


LOLDRIVERS_API = "https://www.loldrivers.io/api/drivers.json"
LOLDRIVERS_CACHE_FILE = Path.home() / ".cache" / "byovd-scanner" / "loldrivers.json"


@dataclass
class LOLDriver:
    """Information about a known vulnerable driver from LOLDrivers."""

    id: str
    name: str
    category: str
    sha256_hashes: List[str]
    sha1_hashes: List[str]
    md5_hashes: List[str]
    authentihash_sha256: List[str]
    commands: List[Dict]
    resources: List[Dict]
    detection_rules: List[Dict]
    known_vuln_samples: List[str]
    tags: List[str]
    verified: bool


class LOLDriversDB:
    """Interface to the LOLDrivers database."""

    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_file = cache_dir / "loldrivers.json" if cache_dir else LOLDRIVERS_CACHE_FILE
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        self._db: Dict[str, LOLDriver] = {}
        self._sha256_index: Dict[str, str] = {}  # sha256 -> driver id
        self._name_index: Dict[str, List[str]] = {}  # name -> driver ids

    def load_from_cache(self) -> bool:
        """Load database from local cache."""
        if not self.cache_file.exists():
            return False

        try:
            with open(self.cache_file, "r") as f:
                data = json.load(f)
            self._parse_drivers(data)
            return True
        except Exception:
            return False

    def update(self, force: bool = False) -> bool:
        """Download latest database from LOLDrivers."""
        if not force and self.cache_file.exists():
            # Check if cache is less than 24 hours old
            import time

            cache_age = time.time() - self.cache_file.stat().st_mtime
            if cache_age < 86400:  # 24 hours
                return self.load_from_cache()

        try:
            response = httpx.get(LOLDRIVERS_API, timeout=30)
            response.raise_for_status()
            data = response.json()

            # Save to cache
            with open(self.cache_file, "w") as f:
                json.dump(data, f)

            self._parse_drivers(data)
            return True
        except Exception as e:
            print(f"[-] Failed to update LOLDrivers DB: {e}")
            # Try loading from cache as fallback
            return self.load_from_cache()

    def _parse_drivers(self, data: List[Dict]):
        """Parse driver data from JSON."""
        self._db.clear()
        self._sha256_index.clear()
        self._name_index.clear()

        for entry in data:
            driver_id = entry.get("Id", "")
            if not driver_id:
                continue

            # Extract hashes from KnownVulnerableSamples
            sha256_hashes = []
            sha1_hashes = []
            md5_hashes = []
            authentihash = []

            for sample in entry.get("KnownVulnerableSamples", []):
                if sample.get("SHA256"):
                    sha256_hashes.append(sample["SHA256"].lower())
                if sample.get("SHA1"):
                    sha1_hashes.append(sample["SHA1"].lower())
                if sample.get("MD5"):
                    md5_hashes.append(sample["MD5"].lower())
                if sample.get("Authentihash", {}).get("SHA256"):
                    authentihash.append(sample["Authentihash"]["SHA256"].lower())

            driver = LOLDriver(
                id=driver_id,
                name=entry.get("Tags", [entry.get("Id", "")])[0] if entry.get("Tags") else entry.get("Id", ""),
                category=entry.get("Category", ""),
                sha256_hashes=sha256_hashes,
                sha1_hashes=sha1_hashes,
                md5_hashes=md5_hashes,
                authentihash_sha256=authentihash,
                commands=entry.get("Commands", []),
                resources=entry.get("Resources", []),
                detection_rules=entry.get("Detection", []),
                known_vuln_samples=[s.get("Filename", "") for s in entry.get("KnownVulnerableSamples", [])],
                tags=entry.get("Tags", []),
                verified=entry.get("Verified", "") == "TRUE",
            )

            self._db[driver_id] = driver

            # Build indices
            for h in sha256_hashes:
                self._sha256_index[h] = driver_id

            name_lower = driver.name.lower()
            if name_lower not in self._name_index:
                self._name_index[name_lower] = []
            self._name_index[name_lower].append(driver_id)

    def lookup_by_hash(self, sha256: str) -> Optional[LOLDriver]:
        """Look up a driver by its SHA256 hash."""
        driver_id = self._sha256_index.get(sha256.lower())
        if driver_id:
            return self._db.get(driver_id)
        return None

    def lookup_by_name(self, name: str) -> List[LOLDriver]:
        """Look up drivers by name (case-insensitive)."""
        driver_ids = self._name_index.get(name.lower(), [])
        return [self._db[did] for did in driver_ids if did in self._db]

    def search(self, query: str) -> List[LOLDriver]:
        """Search for drivers by name or tag."""
        query_lower = query.lower()
        results = []

        for driver in self._db.values():
            if query_lower in driver.name.lower():
                results.append(driver)
                continue
            for tag in driver.tags:
                if query_lower in tag.lower():
                    results.append(driver)
                    break

        return results

    def get_all(self) -> List[LOLDriver]:
        """Get all drivers in the database."""
        return list(self._db.values())

    @property
    def count(self) -> int:
        """Number of drivers in database."""
        return len(self._db)


def check_driver_against_loldrivers(
    sha256: str, driver_name: Optional[str] = None
) -> Optional[Dict]:
    """
    Quick check if a driver matches any known LOLDriver.

    Returns match info if found, None otherwise.
    """
    db = LOLDriversDB()
    if not db.load_from_cache():
        db.update()

    # Try hash lookup first
    match = db.lookup_by_hash(sha256)
    if match:
        return {
            "id": match.id,
            "name": match.name,
            "category": match.category,
            "verified": match.verified,
            "match_type": "sha256",
            "tags": match.tags,
        }

    # Try name lookup
    if driver_name:
        matches = db.lookup_by_name(Path(driver_name).stem)
        if matches:
            return {
                "id": matches[0].id,
                "name": matches[0].name,
                "category": matches[0].category,
                "verified": matches[0].verified,
                "match_type": "name",
                "tags": matches[0].tags,
            }

    return None
