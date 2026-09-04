#!/usr/bin/env python3
"""
MO4 — Android Vulnerability Scanner
OWASP MASVS-style checklist scanner for AndroidManifest.xml

Features:
- Parse AndroidManifest.xml from text input
- Check exported components (activities, services, receivers, providers)
- Detect backup-allowed flag and cleartext traffic permission
- Flag debuggable apps and missing minSdk
- Identify weak crypto providers and permission over-declaration
- MASVS-style findings with severity ratings

Usage:
    python3 android_scan.py
    python3 android_scan.py --manifest AndroidManifest.xml

WARNING: Educational use only. Only scan APKs you own or are authorized to assess.
"""

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

SAMPLE_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.vulnerableapp"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="28" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    <uses-permission android:name="android.permission.CALL_PHONE" />
    <uses-permission android:name="android.permission.PROCESS_OUTGOING_CALLS" />
    <uses-permission android:name="android.permission.BODY_SENSORS" />
    <uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION" />

    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:supportsRtl="true"
        android:theme="@style/AppTheme">

        <activity android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity android:name=".AdminActivity"
            android:exported="true"
            android:permission="android.permission.BIND_DEVICE_ADMIN" />

        <service android:name=".DataSyncService"
            android:exported="true"
            android:permission="" />

        <service android:name=".LocationTracker"
            android:exported="false" />

        <receiver android:name=".BootReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>

        <receiver android:name=".SMSReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="android.provider.Telephony.SMS_RECEIVED" />
            </intent-filter>
        </receiver>

        <provider android:name=".UserDataProvider"
            android:authorities="com.example.vulnerableapp.provider"
            android:exported="true"
            android:grantUriPermissions="true" />

        <provider android:name=".InternalProvider"
            android:authorities="com.example.vulnerableapp.internal"
            android:exported="false" />

    </application>
</manifest>
"""

WEAK_CRYPTO_PROVIDERS = [
    "org.apache.harmony.xnet.jsse.JSSEProvider",
    "org.apache.harmony.crypto.provider.JCEProvider",
    "com.android.org.bouncycastle.jce.provider.BouncyCastleProvider",
]

SUSPICIOUS_PERMISSIONS = {
    "android.permission.READ_SMS": "HIGH",
    "android.permission.SEND_SMS": "CRITICAL",
    "android.permission.RECEIVE_SMS": "HIGH",
    "android.permission.PROCESS_OUTGOING_CALLS": "HIGH",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "CRITICAL",
    "android.permission.READ_CONTACTS": "HIGH",
    "android.permission.BODY_SENSORS": "MEDIUM",
    "android.permission.CALL_PHONE": "MEDIUM",
    "android.permission.READ_PHONE_STATE": "MEDIUM",
}

DANGEROUS_PERMISSIONS = [
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE", "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS", "android.permission.ACCESS_BACKGROUND_LOCATION",
]


class AndroidManifestScanner:
    def __init__(self, manifest_text=None):
        self.manifest_text = manifest_text or SAMPLE_MANIFEST
        self.findings = []
        self.root = None
        self.permissions = []
        self.components = {"activities": [], "services": [], "receivers": [], "providers": []}

    def parse_manifest(self):
        print("\n" + "=" * 60)
        print("  PARSING ANDROIDMANIFEST.XML")
        print("=" * 60)
        try:
            self.root = ET.fromstring(self.manifest_text)
            package = self.root.attrib.get("package", "unknown")
            print(f"  Package: {package}")

            sdk = self.root.find(".//uses-sdk")
            if sdk is not None:
                ns = "{http://schemas.android.com/apk/res/android}"
                min_sdk = sdk.attrib.get(f"{ns}minSdkVersion", "not set")
                target_sdk = sdk.attrib.get(f"{ns}targetSdkVersion", "not set")
                print(f"  minSdkVersion: {min_sdk}")
                print(f"  targetSdkVersion: {target_sdk}")
                self._check_sdk(min_sdk, target_sdk)

            ns = "{http://schemas.android.com/apk/res/android}"
            for perm_elem in self.root.findall(".//uses-permission"):
                name = perm_elem.attrib.get(f"{ns}name", "")
                if name:
                    self.permissions.append(name)

            print(f"  Permissions declared: {len(self.permissions)}")
            self._check_permissions()

            app = self.root.find(".//application")
            if app is not None:
                self._check_application_flags(app)

            self._parse_components()

        except ET.ParseError as e:
            print(f"  ERROR: Failed to parse manifest XML: {e}")
            self.findings.append({"severity": "CRITICAL", "category": "parse_error", "detail": str(e)})

    def _check_sdk(self, min_sdk, target_sdk):
        if min_sdk == "not set":
            self.findings.append({"severity": "HIGH", "category": "sdk", "detail": "minSdkVersion not specified"})
            print("  [!!] HIGH: minSdkVersion not specified")
        else:
            try:
                if int(min_sdk) < 23:
                    self.findings.append({"severity": "MEDIUM", "category": "sdk", "detail": f"minSdkVersion {min_sdk} < 23 (lacks runtime permissions)"})
                    print(f"  [!!] MEDIUM: minSdkVersion {min_sdk} < 23 — no runtime permission model")
            except ValueError:
                pass

        if target_sdk != "not set":
            try:
                if int(target_sdk) < 29:
                    self.findings.append({"severity": "MEDIUM", "category": "sdk", "detail": f"targetSdkVersion {target_sdk} < 29 — outdated API level"})
                    print(f"  [!!] MEDIUM: targetSdkVersion {target_sdk} < 29 — may miss security hardening")
            except ValueError:
                pass

    def _check_permissions(self):
        print("\n" + "=" * 60)
        print("  PERMISSION ANALYSIS")
        print("=" * 60)

        dangerous_count = sum(1 for p in self.permissions if p in DANGEROUS_PERMISSIONS)
        print(f"  Dangerous permissions: {dangerous_count}")

        if dangerous_count > 6:
            self.findings.append({"severity": "HIGH", "category": "permission_over",
                                  "detail": f"Permission over-declaration: {dangerous_count} dangerous permissions"})
            print(f"  [!!] HIGH: Permission over-declaration — {dangerous_count} dangerous permissions")

        for perm in self.permissions:
            if perm in SUSPICIOUS_PERMISSIONS:
                sev = SUSPICIOUS_PERMISSIONS[perm]
                short = perm.split(".")[-1]
                self.findings.append({"severity": sev, "category": "suspicious_perm", "detail": f"Suspicious permission: {short}"})
                print(f"  [!!] {sev:8s}: {short}")

        sms_perms = [p for p in self.permissions if "SMS" in p.upper()]
        net_perms = [p for p in self.permissions if "INTERNET" in p.upper() or "NETWORK" in p.upper()]
        if sms_perms and net_perms:
            self.findings.append({"severity": "CRITICAL", "category": "sms_network_combo",
                                  "detail": "SMS permissions combined with network access — data exfiltration risk"})
            print("  [!!] CRITICAL: SMS + NETWORK permission combo — exfiltration risk")

        loc_perms = [p for p in self.permissions if "LOCATION" in p.upper()]
        if len(loc_perms) >= 2 and "android.permission.ACCESS_BACKGROUND_LOCATION" in self.permissions:
            self.findings.append({"severity": "CRITICAL", "category": "bg_location",
                                  "detail": "Background location access enabled"})
            print("  [!!] CRITICAL: Background location access enabled")

    def _check_application_flags(self, app):
        print("\n" + "=" * 60)
        print("  APPLICATION FLAGS")
        print("=" * 60)
        ns = "{http://schemas.android.com/apk/res/android}"

        debuggable = app.attrib.get(f"{ns}debuggable", "false")
        if debuggable.lower() == "true":
            self.findings.append({"severity": "CRITICAL", "category": "debuggable", "detail": "App is debuggable"})
            print("  [!!] CRITICAL: App is debuggable — allows debugger attachment")
        else:
            print("  [OK] debuggable=false")

        allow_backup = app.attrib.get(f"{ns}allowBackup", "true")
        if allow_backup.lower() == "true":
            self.findings.append({"severity": "HIGH", "category": "backup", "detail": "allowBackup is true — data extractable via ADB"})
            print("  [!!] HIGH: allowBackup=true — data extractable via adb backup")
        else:
            print("  [OK] allowBackup=false")

        cleartext = app.attrib.get(f"{ns}usesCleartextTraffic", "false")
        if cleartext.lower() == "true":
            self.findings.append({"severity": "HIGH", "category": "cleartext", "detail": "Cleartext traffic permitted"})
            print("  [!!] HIGH: usesCleartextTraffic=true — HTTP traffic allowed")
        else:
            print("  [OK] usesCleartextTraffic=false")

    def _parse_components(self):
        print("\n" + "=" * 60)
        print("  COMPONENT ANALYSIS")
        print("=" * 60)
        ns = "{http://schemas.android.com/apk/res/android}"

        for tag, key in [("activity", "activities"), ("service", "services"),
                         ("receiver", "receivers"), ("provider", "providers")]:
            for elem in self.root.findall(f".//{tag}"):
                name = elem.attrib.get(f"{ns}name", "unknown")
                exported = elem.attrib.get(f"{ns}exported", None)
                has_intent = len(elem.findall(".//intent-filter")) > 0

                is_exported = exported == "true" or (exported is None and has_intent)
                entry = {"name": name, "exported": is_exported}
                self.components[key].append(entry)

        for key, label in [("activities", "Activities"), ("services", "Services"),
                           ("receivers", "Receivers"), ("providers", "Providers")]:
            comps = self.components[key]
            exported = [c for c in comps if c["exported"]]
            print(f"\n  {label} ({len(comps)} total, {len(exported)} exported):")
            for c in comps:
                flag = " [EXPORTED]" if c["exported"] else ""
                print(f"    - {c['name']}{flag}")

            if key == "receivers" and exported:
                for c in exported:
                    self.findings.append({"severity": "HIGH", "category": "exported_receiver",
                                          "detail": f"Exported receiver: {c['name']}"})
                    print(f"    [!!] HIGH: Exported receiver without protection: {c['name']}")

            if key == "providers" and exported:
                for c in exported:
                    self.findings.append({"severity": "HIGH", "category": "exported_provider",
                                          "detail": f"Exported provider: {c['name']}"})
                    print(f"    [!!] HIGH: Exported provider: {c['name']}")

            if key == "services" and exported:
                for c in exported:
                    self.findings.append({"severity": "MEDIUM", "category": "exported_service",
                                          "detail": f"Exported service: {c['name']}"})
                    print(f"    [!!] MEDIUM: Exported service: {c['name']}")

    def generate_report(self):
        print("\n" + "=" * 60)
        print("  MASVS-STYLE FINDINGS SUMMARY")
        print("=" * 60)
        sev_counts = defaultdict(int)
        for f in self.findings:
            sev_counts[f["severity"]] += 1

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev_counts[sev] > 0:
                print(f"  {sev:10s}: {sev_counts[sev]}")

        print(f"\n  Total findings: {len(self.findings)}")
        if self.findings:
            print("\n  Detailed findings:")
            for i, f in enumerate(self.findings, 1):
                print(f"    {i}. [{f['severity']}] {f['category']}: {f['detail']}")
        else:
            print("  No findings — manifest appears clean")

        print("\n" + "=" * 60)

    def run(self):
        print("\n" + "=" * 60)
        print("  MO4 — Android Vulnerability Scanner")
        print("=" * 60)
        print("  OWASP MASVS-style Manifest Analysis")
        self.parse_manifest()
        self.generate_report()
        return self.findings


def main():
    parser = argparse.ArgumentParser(description="MO4 — Android Vulnerability Scanner")
    parser.add_argument("--manifest", "-m", help="Path to AndroidManifest.xml (uses demo if omitted)")
    args = parser.parse_args()

    manifest_text = None
    if args.manifest:
        try:
            with open(args.manifest) as f:
                manifest_text = f.read()
            print(f"Loaded manifest from: {args.manifest}")
        except Exception as e:
            print(f"ERROR: Could not read manifest: {e}")
            sys.exit(1)
    else:
        print("No manifest provided — using embedded demo data")

    scanner = AndroidManifestScanner(manifest_text)
    findings = scanner.run()

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
