# MO4 — Android Vulnerability Scanner

OWASP MASVS-style checklist scanner for AndroidManifest.xml security analysis.

## Overview

This project implements an automated Android manifest vulnerability scanner that:
- Parses AndroidManifest.xml from text input or uses an embedded sample
- Checks exported components (activities, services, receivers, providers)
- Detects backup-allowed flag and cleartext traffic permission
- Flags debuggable apps, missing minSdk, and outdated targetSdk
- Identifies suspicious permission combinations (SMS + network, background location)
- Detects permission over-declaration patterns
- Produces MASVS-style findings with severity ratings

## Features

- **Manifest Parsing**: Full AndroidManifest.xml XML parsing with namespace support
- **Exported Component Detection**: Activities, services, receivers, providers with intent-filter analysis
- **Application Flags**: debuggable, allowBackup, usesCleartextTraffic checks
- **SDK Analysis**: minSdkVersion and targetSdkVersion security review
- **Permission Analysis**: Dangerous permission counting, suspicious combos, over-declaration
- **MASVS-Style Findings**: CRITICAL/HIGH/MEDIUM severity ratings with categories

## Dependencies

**None** — uses only Python standard library (`xml.etree.ElementTree`, `re`, `argparse`, `collections`).

## Installation

```bash
# No external dependencies required
python3 android_scan.py
```

## Usage

```bash
# Run demo with embedded vulnerable manifest
python3 android_scan.py

# Scan a specific manifest file
python3 android_scan.py --manifest AndroidManifest.xml
```

## Example Output

```
============================================================
  MO4 — Android Vulnerability Scanner
============================================================
  OWASP MASVS-style Manifest Analysis

============================================================
  PARSING ANDROIDMANIFEST.XML
============================================================
  Package: com.example.vulnerableapp
  minSdkVersion: 21
  targetSdkVersion: 28
  Permissions declared: 16

============================================================
  PERMISSION ANALYSIS
============================================================
  [!!] HIGH: Permission over-declaration — 15 dangerous permissions
  [!!] CRITICAL: SEND_SMS
  [!!] CRITICAL: SMS + NETWORK permission combo — exfiltration risk
  [!!] CRITICAL: Background location access enabled

============================================================
  APPLICATION FLAGS
============================================================
  [!!] CRITICAL: App is debuggable — allows debugger attachment
  [!!] HIGH: allowBackup=true — data extractable via adb backup
  [!!] HIGH: usesCleartextTraffic=true — HTTP traffic allowed

  MASVS-STYLE FINDINGS SUMMARY
  CRITICAL  : 5
  HIGH      : 10
  MEDIUM    : 6
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the app owner before using this tool
- Unauthorized reverse engineering of mobile apps may violate applicable laws
- This tool should ONLY be used on APKs you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **DMCA (17 U.S.C. § 1201)**: Circumventing software protection measures may violate copyright law
- **State Laws**: Many states have additional computer crime and reverse engineering statutes
- **OWASP MASVS**: Findings align with Mobile Application Security Verification Standard

### Acceptable Use
- Security assessment of your own Android applications
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Scanning or reverse engineering apps you do not own
- Distributing exploits or vulnerability details publicly
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the app developer privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
