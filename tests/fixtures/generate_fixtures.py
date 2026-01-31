#!/usr/bin/env python3
"""Generate static parquet test fixtures for cvecli tests.

This script creates a comprehensive set of test data that covers various
edge cases and scenarios. The fixtures are stored as static parquet files
to ensure test reproducibility and speed.

Run this script to regenerate fixtures after schema changes:
    uv run python tests/fixtures/generate_fixtures.py
"""

from pathlib import Path

import polars as pl

FIXTURES_DIR = Path(__file__).parent / "data"


def create_cves_fixture() -> pl.DataFrame:
    """Create the main CVEs table with various test scenarios."""
    return pl.DataFrame(
        {
            "cve_id": [
                # Different years for date filtering tests
                "CVE-2016-7054",  # OpenSSL ChaCha20/Poly1305
                "CVE-2019-11510",  # Pulse Secure VPN
                "CVE-2021-44228",  # Log4Shell
                "CVE-2022-2196",  # KVM vulnerability
                "CVE-2023-0001",  # Test case with no severity
                "CVE-2024-1234",  # Test case with ADP metrics
                "CVE-2024-5678",  # Test case with PURL
                "CVE-2024-9999",  # Rejected CVE
                "CVE-2025-0001",  # Recent CVE for date range tests
            ],
            "state": [
                "PUBLISHED",
                "PUBLISHED",
                "PUBLISHED",
                "PUBLISHED",
                "PUBLISHED",
                "PUBLISHED",
                "PUBLISHED",
                "REJECTED",
                "PUBLISHED",
            ],
            "assigner_org_id": [
                "3a12439a-4ef3-4c79-92e6-6081a721f1e5",  # OpenSSL
                "827a3c94-5f54-41d3-b5d4-7f4f1e8b5e52",  # Pulse
                "14ed7db2-1595-443d-9d34-6215bf890778",  # Apache
                "14ed7db2-1595-443d-9d34-6215bf890778",  # Google
                "14ed7db2-4595-443d-9d34-6215bf890778",  # Test
                "14ed7db2-4595-443d-9d34-6215bf890778",  # Test
                "14ed7db2-4595-443d-9d34-6215bf890778",  # Test
                "14ed7db2-4595-443d-9d34-6215bf890778",  # Test
                "14ed7db2-4595-443d-9d34-6215bf890778",  # Test
            ],
            "assigner_short_name": [
                "openssl",
                "Pulse Secure",
                "Apache",
                "Google",
                "test",
                "test",
                "test",
                "test",
                "test",
            ],
            "date_reserved": [
                None,
                "2019-04-22T00:00:00.000Z",
                "2021-11-26T00:00:00.000Z",
                "2022-06-24T13:29:09.969Z",
                None,
                None,
                None,
                None,
                "2025-01-01T00:00:00.000Z",
            ],
            "date_published": [
                "2017-05-04T00:00:00.000Z",
                "2019-05-09T00:00:00.000Z",
                "2021-12-10T00:00:00.000Z",
                "2023-01-09T10:59:53.099Z",
                "2023-01-01T00:00:00.000Z",
                "2024-06-01T00:00:00.000Z",
                "2024-07-15T00:00:00.000Z",
                "2024-07-01T00:00:00.000Z",
                "2025-01-15T00:00:00.000Z",
            ],
            "date_updated": [
                None,
                "2024-08-13T08:20:20.377Z",
                "2025-01-18T15:38:46.768Z",
                "2025-02-13T16:28:57.097Z",
                None,
                None,
                None,
                None,
                None,
            ],
            "cna_title": [
                "ChaCha20/Poly1305 heap-buffer-overflow",
                "Pulse Secure VPN Arbitrary File Read",
                "Apache Log4j2 Remote Code Execution",
                "KVM nVMX Spectre v2 vulnerability",
                None,
                "Test with ADP metrics",
                "Python requests PURL example",
                "Rejected test CVE",
                "Recent vulnerability for testing",
            ],
        }
    )


def create_descriptions_fixture() -> pl.DataFrame:
    """Create CVE descriptions table."""
    return pl.DataFrame(
        {
            "cve_id": [
                "CVE-2016-7054",
                "CVE-2019-11510",
                "CVE-2021-44228",
                "CVE-2022-2196",
                "CVE-2023-0001",
                "CVE-2024-1234",
                "CVE-2024-5678",
                "CVE-2025-0001",
            ],
            "lang": ["en"] * 8,
            "value": [
                "ChaCha20/Poly1305 heap-buffer-overflow in OpenSSL 1.1.0.",
                "In Pulse Secure Pulse Connect Secure before 9.0R3.4, an unauthenticated remote attacker can read arbitrary files via specially crafted URI.",
                "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding 2.12.3) JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                "A regression exists in the Linux Kernel within KVM. Spectre v2 mitigations are not applied to nested VMs.",
                "Test vulnerability with no severity information.",
                "Test vulnerability with ADP metrics from CISA.",
                "Security vulnerability in Python requests library affecting HTTPS certificate validation.",
                "Recent vulnerability for date range testing.",
            ],
            "source": ["cna"] * 8,
        }
    )


def create_metrics_fixture() -> pl.DataFrame:
    """Create CVE metrics table with various CVSS versions and sources."""
    return pl.DataFrame(
        {
            "cve_id": [
                "CVE-2016-7054",  # Text severity only
                "CVE-2019-11510",  # CVSS 3.1 critical
                "CVE-2021-44228",  # CVSS 3.1 critical (Log4Shell)
                "CVE-2022-2196",  # CVSS 3.1 medium
                "CVE-2024-1234",  # ADP CVSS critical
                "CVE-2024-1234",  # KEV entry
                "CVE-2024-1234",  # SSVC entry
                "CVE-2024-5678",  # CVSS 3.1 medium
                "CVE-2025-0001",  # CVSS 4.0 example
            ],
            "metric_type": [
                "other",
                "cvssV3_1",
                "cvssV3_1",
                "cvssV3_1",
                "cvssV3_1",
                "other",
                "other",
                "cvssV3_1",
                "cvssV4_0",
            ],
            "source": [
                "cna",
                "cna",
                "cna",
                "cna",
                "adp:CISA-ADP",
                "adp:CISA-ADP",
                "adp:CISA-ADP",
                "cna",
                "cna",
            ],
            "base_score": [
                None,
                10.0,
                10.0,
                5.8,
                9.8,
                None,
                None,
                6.1,
                8.7,
            ],
            "base_severity": [
                "High",  # Text severity
                "CRITICAL",
                "CRITICAL",
                "MEDIUM",
                "CRITICAL",
                None,
                None,
                "MEDIUM",
                "HIGH",
            ],
            "vector_string": [
                None,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                None,
                None,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            ],
            "attack_vector": [
                None,
                "NETWORK",
                "NETWORK",
                "LOCAL",
                "NETWORK",
                None,
                None,
                "NETWORK",
                "NETWORK",
            ],
            "attack_complexity": [
                None,
                "LOW",
                "LOW",
                "HIGH",
                "LOW",
                None,
                None,
                "LOW",
                "LOW",
            ],
            "privileges_required": [
                None,
                "NONE",
                "NONE",
                "LOW",
                "NONE",
                None,
                None,
                "NONE",
                "NONE",
            ],
            "user_interaction": [
                None,
                "NONE",
                "NONE",
                "NONE",
                "NONE",
                None,
                None,
                "REQUIRED",
                "NONE",
            ],
            "scope": [
                None,
                "CHANGED",
                "CHANGED",
                "UNCHANGED",
                "UNCHANGED",
                None,
                None,
                "CHANGED",
                None,
            ],
            "confidentiality_impact": [
                None,
                "HIGH",
                "HIGH",
                "LOW",
                "HIGH",
                None,
                None,
                "LOW",
                "HIGH",
            ],
            "integrity_impact": [
                None,
                "HIGH",
                "HIGH",
                "HIGH",
                "HIGH",
                None,
                None,
                "LOW",
                "HIGH",
            ],
            "availability_impact": [
                None,
                "HIGH",
                "HIGH",
                "LOW",
                "HIGH",
                None,
                None,
                "NONE",
                "NONE",
            ],
            "exploit_maturity": [None] * 9,
            "exploitability_score": [None] * 9,
            "impact_score": [None] * 9,
            "other_type": [
                None,
                None,
                None,
                None,
                None,
                "kev",
                "ssvc",
                None,
                None,
            ],
            "other_content": [
                None,
                None,
                None,
                None,
                None,
                '{"dateAdded": "2024-01-15", "reference": "https://cisa.gov/kev"}',
                '{"automatable": "Yes", "exploitation": "Active", "technicalImpact": "Total"}',
                None,
                None,
            ],
        }
    )


def create_products_fixture() -> pl.DataFrame:
    """Create CVE products table."""
    return pl.DataFrame(
        {
            "cve_id": [
                "CVE-2016-7054",
                "CVE-2019-11510",
                "CVE-2021-44228",
                "CVE-2022-2196",
                "CVE-2023-0001",
                "CVE-2024-1234",
                "CVE-2024-5678",
                "CVE-2024-9999",
                "CVE-2025-0001",
            ],
            "product_id": [1, 2, 3, 4, 5, 6, 7, 8, 9],
            "vendor": [
                "OpenSSL",
                "Pulse Secure",
                "Apache",
                "Linux",
                "TestVendor",
                "SomeVendor",
                "Python",
                "Test.Vendor (Inc.)",  # Regex special chars for escaping tests
                "TestCorp",
            ],
            "product": [
                "OpenSSL",
                "Pulse Connect Secure",
                "Log4j",
                "Linux Kernel",
                "TestProduct",
                "SomeProduct",
                "requests",
                "Product[v1.0]+",  # Regex special chars for escaping tests
                "TestApp",
            ],
            "package_name": [
                None,
                None,
                "log4j-core",
                "KVM",
                None,
                None,
                None,
                None,
                None,
            ],
            "cpes": [
                None,
                "cpe:2.3:a:pulsesecure:pulse_connect_secure:*:*:*:*:*:*:*:*",
                "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
                None,
                None,
                None,
            ],
            "modules": [None] * 9,
            "program_files": [None] * 9,
            "program_routines": [None] * 9,
            "platforms": [None] * 9,
            "repo": [None] * 9,
            "default_status": [
                None,
                None,
                None,
                "unaffected",
                None,
                None,
                None,
                None,
                None,
            ],
            "source": ["cna"] * 9,
            "package_url": [
                None,
                None,
                "pkg:maven/org.apache.logging.log4j/log4j-core",
                None,
                "pkg:pypi/django",
                "pkg:npm/lodash",
                "pkg:pypi/requests",
                "pkg:maven/org.apache.xmlgraphics/batik-anim",
                "pkg:npm/test-package",
            ],
        }
    )


def create_versions_fixture() -> pl.DataFrame:
    """Create CVE versions table."""
    return pl.DataFrame(
        {
            "cve_id": [
                "CVE-2016-7054",
                "CVE-2019-11510",
                "CVE-2019-11510",
                "CVE-2021-44228",
                "CVE-2021-44228",
                "CVE-2022-2196",
                "CVE-2024-5678",
            ],
            "product_id": [1, 2, 2, 3, 3, 4, 7],
            "version": [
                "1.1.0",
                "8.1",
                "8.2",
                "2.0-beta9",
                "2.12.0",
                "0",
                "0",
            ],
            "version_type": [
                None,
                "custom",
                "custom",
                "semver",
                "semver",
                "custom",
                "semver",
            ],
            "status": [
                "affected",
                "affected",
                "affected",
                "affected",
                "affected",
                "affected",
                "affected",
            ],
            "less_than": [
                None,
                "9.0R3.4",
                "8.2R12.1",
                "2.15.0",
                "2.12.3",
                "6.2",
                "2.32.0",
            ],
            "less_than_or_equal": [None] * 7,
            "source": ["cna"] * 7,
        }
    )


def create_cwes_fixture() -> pl.DataFrame:
    """Create CVE-CWE mapping table."""
    return pl.DataFrame(
        {
            "cve_id": [
                "CVE-2016-7054",
                "CVE-2019-11510",
                "CVE-2021-44228",
                "CVE-2021-44228",
                "CVE-2022-2196",
            ],
            "cwe_id": [
                "CWE-119",
                "CWE-22",
                "CWE-502",
                "CWE-917",
                "CWE-1188",
            ],
            "description": [
                "CWE-119 Buffer Errors",
                "CWE-22 Path Traversal",
                "CWE-502 Deserialization of Untrusted Data",
                "CWE-917 Expression Language Injection",
                "CWE-1188 Insecure Default Initialization",
            ],
            "lang": ["en"] * 5,
            "type": ["CWE"] * 5,
            "source": ["cna"] * 5,
        }
    )


def create_references_fixture() -> pl.DataFrame:
    """Create CVE references table."""
    return pl.DataFrame(
        {
            "cve_id": [
                "CVE-2016-7054",
                "CVE-2019-11510",
                "CVE-2021-44228",
                "CVE-2022-2196",
                "CVE-2024-5678",
            ],
            "url": [
                "https://www.openssl.org/news/secadv/20161110.txt",
                "https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101",
                "https://logging.apache.org/log4j/2.x/security.html",
                "https://kernel.dance/#2e7eab81425a",
                "https://github.com/psf/requests/security",
            ],
            "name": [None] * 5,
            "tags": [None] * 5,
            "source": ["cna"] * 5,
        }
    )


def create_credits_fixture() -> pl.DataFrame:
    """Create empty CVE credits table with correct schema."""
    return pl.DataFrame(
        schema={
            "cve_id": pl.Utf8,
            "lang": pl.Utf8,
            "value": pl.Utf8,
            "type": pl.Utf8,
            "user_uuid": pl.Utf8,
            "source": pl.Utf8,
        }
    )


def create_tags_fixture() -> pl.DataFrame:
    """Create empty CVE tags table with correct schema."""
    return pl.DataFrame(
        schema={
            "cve_id": pl.Utf8,
            "tag": pl.Utf8,
            "source": pl.Utf8,
        }
    )


def generate_all_fixtures() -> None:
    """Generate all test fixtures and write to parquet files."""
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    fixtures = {
        "cves.parquet": create_cves_fixture(),
        "cve_descriptions.parquet": create_descriptions_fixture(),
        "cve_metrics.parquet": create_metrics_fixture(),
        "cve_products.parquet": create_products_fixture(),
        "cve_versions.parquet": create_versions_fixture(),
        "cve_cwes.parquet": create_cwes_fixture(),
        "cve_references.parquet": create_references_fixture(),
        "cve_credits.parquet": create_credits_fixture(),
        "cve_tags.parquet": create_tags_fixture(),
    }

    for filename, df in fixtures.items():
        filepath = FIXTURES_DIR / filename
        df.write_parquet(filepath)
        print(f"Generated {filepath} ({len(df)} rows)")

    print(f"\nAll fixtures generated in {FIXTURES_DIR}")


if __name__ == "__main__":
    generate_all_fixtures()
