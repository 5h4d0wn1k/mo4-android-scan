# MO4 — Android Vulnerability Scanner

OWASP MASVS-style checklist scanner for `AndroidManifest.xml` and the
`network_security_config.xml` it may reference. Runs offline against fixtures.
Standard-library only.

## What the engine genuinely does

- **Manifest parsing** — real XML parse of `AndroidManifest.xml` (package,
  `uses-sdk`, permissions).
- **Exported component analysis** — activities/services/receivers/providers
  flagged by `android:exported` (with implicit-export by intent-filter logic).
- **Application flags** — `android:debuggable`, `android:allowBackup`,
  `android:usesCleartextTraffic`.
- **Network security config** — parses `res/xml/network_security_config.xml`:
  `base-config` / `domain-config` cleartext permissions, user-supplied CAs
  (`trust-anchors`), `pin-set` expiry.
- **Permission posture** — dangerous-permission counting, SUSPICIOUS permission
  tiers, SMS+network exfiltration combo, background location.
- **SDK checks** — `minSdkVersion < 23`, outdated `targetSdkVersion`.
- **Findings** — MASVS-style severities (`CRITICAL`..`INFO`) plus a JSON summary.

## Quick start

```bash
# Offline demo (scans fixture manifests+netsec, writes reports/, exit 0)
python3 firmware/android_scan.py

# Scan a real manifest with its network security config
python3 firmware/android_scan.py --manifest AndroidManifest.xml \
    --netsec-config res/xml/network_security_config.xml --json

# Rebuild fixtures
python3 firmware/android_scan.py --make-fixture

# Tests
python3 -m unittest discover -s tests
```

## CLI

```
python3 firmware/android_scan.py [-h] [-m MANIFEST] [--netsec-config NETSEC_CONFIG]
                                 [--json] [--report-dir REPORT_DIR] [--make-fixture]
```

- `--manifest/-m` — path to an `AndroidManifest.xml`; omitted → offline demo.
- `--netsec-config` — referenced `network_security_config.xml` to analyze.
- `--json` — write JSON summary to `reports/`.
- `--report-dir` — report directory (default `reports`).
- `--make-fixture` — regenerate fixtures and exit.

Exit codes: `0` success (incl. demo), `2` input error.

## Live Lab Test Plan

Prerequisites: an APK (or just a manifest) you own or are authorized to assess —
the fixture app `com.example.vulnerableapp` stands in offline.

1. **Baseline**: `python3 firmware/android_scan.py` — confirm vulnerable vs.
   hardened fixture findings separate cleanly (vulnerable has CRITICAL+HIGH,
   hardened has < 3 low-severity findings).
2. **Real target**: decompile a permitted app (apktool) and run the scanner on
   its `AndroidManifest.xml` + `res/xml/network_security_config.xml`. Manually
   verify every exported component and cleartext flag against the APK.
3. **Differential**: confirm removing `android:exported="true"` and setting
   `allowBackup=false` removes the corresponding findings (regression guard).
4. **JSON output**: verify `reports/mo4_report.json` contains
   `severity_counts`, `component_counts`, and the full findings array.
5. **Regression**: re-run `python3 -m unittest discover -s tests`.

## Metrics

| Metric                     | Value |
|----------------------------|-------|
| Standard-library only      | Yes   |
| Third-party deps           | none  |
| Deterministic offline tests| 18    |
| Fixtures                   | vulnerable + hardened manifest, netsec config |
| Offline demo exit          | 0     |
| Report output              | `reports/*.json` (gitignored) |
| Inputs                     | AndroidManifest.xml, network_security_config.xml |

## IMPORTANT: Read before use.

Educational, authorization-required tooling. See `LICENSE` for the full shield —
Authorization, CFAA / computer-crime statutes, Acceptable Use, Prohibited Use,
No Warranty, and Responsible Disclosure. Only scan apps you own or are
explicitly authorized to assess.

## License

MIT — full legal shield in `LICENSE`.