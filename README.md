# Introduction to Mobile Application Security and Static Analysis

**Author**: Alper Basaran  
Penetration Tester / Cybersecurity Consultant  
_CISSP | CISA | CPTE | CPTC | eCIR | GPEN | OSWP | GICSP_

---

## Overview

- Mobile OS overview (Android & iOS)
- OWASP Mobile Top 10
- Threat modeling and attack surfaces
- Static & Dynamic analysis techniques

---

## The Bad News

- **Mobile apps are platform dependent**
- Over 8.5 Billion mobile phone users worldwide
- Everyone spends almost 4 hours daily on mobile phones
- Over 88% of this time spent on mobile apps

---

## Mobile Apps Are Everywhere

- Mobile devices create a **new threat landscape**
- Common mobile security challenges:
    - Insecure data storage
    - Weak authentication
    - Excessive app permissions
    - Insecure API
    - Mobile malware
    - Mobile OS vulnerabilities

---

## Mobile Application Security Stakeholders

- Developers
- Organizations
- Users
- Security professionals

---

## Future Trends and Challenges

- IoT integration
- AI impact
- Increased regulations
- BYOD / Zero Trust Security models

---

## What are "apps"?

- Any application that runs on a mobile OS
- Focus: **Android and iOS**

---

## App Types

|                        | Native App      | Hybrid App       | Web App       |
|------------------------|-----------------|------------------|---------------|
| Performance            | +++++           | +++              | ++            |
| Device Access          | Full            | Limited          | Very limited  |
| Security               | High            | Moderate         | Low           |
| Development Time       | Longest         | Mid              | Fastest       |
| Single Code Base?      | No              | Yes              | Yes           |

---

## Mobile App Security Testing

### Why Do We Test?

- Bug bounty, pentesting, consulting: different approaches, same goal.

### Approaches

- Black-box testing (_No knowledge, simulates real attacks_)
- White-box testing (_Source code access, deep analysis_)
- Gray-box testing (_Partial knowledge, realistic attacker simulation_)

### Methods

- Penetration testing
- Vulnerability analysis
- Threat modeling
- Source code analysis

---

## Static vs Dynamic Analysis

|                   | Static Analysis (SAST) | Dynamic Analysis (DAST)  |
|-------------------|-----------------------|--------------------------|
| Execution         | No                    | Yes                      |
| Hardcoded Secrets | Yes                   | No                       |
| Runtime Issues    | No                    | Yes                      |
| API Weaknesses    | Limited               | Yes                      |

---

## Penetration Testing Process

1. Pre-engagement
2. Recon
3. App Mapping
4. Exploitation
5. Reporting

### Pre-engagement

- Know customer & regulation expectations
- Understand & locate sensitive data
- Identify crypto, hashes, tokens, PRNG

---

## The Differences: Web vs Mobile Security

### Web Applications

- Accessed via browser, platform-agnostic
- Focus: server security
- Classic vulns: SQLi, XSS, CSRF

### Mobile Applications

- Installed on device, possibly offline
- Focus: device data, hardware integration
- Vulns: Insecure storage, Reverse engineering, Weak API Security

---

## Understanding Security Best Practices

- Secure SDLC
- Data protection
- Auth & Authz
- Secure communication
- Regular updates
- Code security
- Monitoring, incident response
- Employee training

---

## Common Threats and Vulnerabilities

### Why Mobile Apps Are Targeted

- High value data, wide surface, developer awareness gaps

### Common Vulnerabilities

- Insecure Data Storage
- Insecure Communication
- Weak Authentication & Authorization
- Excessive Permissions
- Insecure APIs
- Reverse Engineering
- Outdated Components

---

## Mitigating Common Vulnerabilities

- Secure Data Storage
- Secure Communication
- Strong Authentication & Authorization
- Secure Code
- Management of Third-Party Libraries

---

## Bug Bounty & Research Reports

- Platforms: HackerOne, Bugcrowd, Synack, etc.
- Reports: Give real-world exploitation scenarios, patterns in vulns

### Common Bug Bounty Vulns

- Insecure Data Storage (e.g. auth tokens in plaintext)
- Improper Authentication (API manipulation)
- API Misconfigurations (Unprotected endpoints)
- Injection (e.g. NoSQLi, data exfiltration)
- Code Obfuscation Failures (hardcoded keys)

---

## Tools and Techniques Used

**Reverse Engineering:** JADX, APKTool, Ghidra  
**Network Analysis:** Burp Suite, Wireshark  
**API Testing:** Postman, OWASP ZAP  
**Runtime Analysis:** Frida, Xposed Framework

---

## Android Platform Architecture

- **Kernel**: Linux-based, not typically relevant for app testing
- **Native Daemons**: Background processes, kernel interaction
- **HAL**: Hardware Abstraction Layer for device-specific features
- **ART**: Android Runtime translates bytecode to processor instructions
- **System Services**: Power manager, account manager, alarms, notifications, etc.
- **Android Framework:** Java classes & interfaces; building blocks for apps
- **Android API/System API**: Entry points for app development

---

## App Components

- **Activities**: Single screens, user interaction
- **Services**: Background logic
- **Broadcast Receivers**: System event handling
- **Content Providers**: Shared data management (contacts, etc.)

---

## Android Security Features

#### System-wide

- **Device encryption** (full disk/file)
- **Trusted Execution Environment (TEE)**
- **Verified Boot**

#### Software Isolation

- App sandboxes (unique user per app)
- SELinux - Mandatory access control
- Permissions (Install-time, runtime, special, signature)

#### Network

- TLS by default
- DNS over TLS

#### Anti-exploitation

- ASLR/KASLR/PIE/DEP
- SECCOMP (Syscall filtering)

---

## App Distribution Formats

- **APK:** Android Package Kit (classic)
- **AAB:** Android App Bundle (optimized by Play Store)

---

## AndroidManifest.xml

- **Defines:**  
    - Components (Activity, Service, Receiver, Provider)
    - Permissions
    - Features and APIs

---

## Risky Permissions

- Device Admin / Accessibility
- Data theft & privacy (contacts, SMS, call logs, audio, location)
- File system (read/write storage)
- Network (INTERNET, network state, Wi-Fi)
- System (WAKE_LOCK, REBOOT, INSTALL_PACKAGES)

---

## Exported Components

| Component                 | Risk                      | Mitigation                             |
|---------------------------|---------------------------|----------------------------------------|
| Exported Activities       | UI hijack, intent inject  | Set exported="false" unless needed     |
| Exported Services         | Remote code exec          | Restrict with permissions              |
| Exported Broadcast Recvs  | Intent hijack             | Use explicit broadcasts, exported=false|
| Exported Content Providers| Data leakage              | exported="false", permissions          |

---

## Other Android Manifest Security Risks

- Debuggable apps (adb attachable)
- Backup enabled (adb backup extraction)
- Cleartext traffic allowed
- Misconfigured URI permissions

---

## iOS App Architecture & Security

- **Code signing:** Only Apple-approved code
- **Encryption:** Hardware, file-based; uses device UID and passcode
- **Sandbox:** App data isolated per app, with exceptions for user-approved system access
- **Exploit mitigations:** ASLR, eXecute Never (XN)
- **App distribution:** IPA file (zipped app bundle, code signature)

---

## iOS App Permissions & Info.plist

- Permission dialog at runtime (location, contacts, microphone, camera, etc.)
- **Info.plist:** App configuration, security and network flags

#### Info.plist Risks

| Setting                           | Risk                                        |
|------------------------------------|---------------------------------------------|
| UIFileSharingEnabled               | iTunes file access (data theft)             |
| LSSupportsOpeningDocumentsInPlace  | Modify/read files in iCloud/other apps      |
| NSAllowsArbitraryLoads             | Allows insecure HTTP (MitM attacks)         |
| NSCameraUsageDescription           | Requests camera access (spying risk)        |
| CFBundleURLTypes (Deep Linking)    | Unvalidated input, deep link hijacking      |

---

## Secure App Development Lifecycle

1. **Idea and Planning:** Develop security plan
2. **Design:** Secure by design (least privilege, role, etc.)
3. **Development:** Secure coding
4. **Testing:** Security testing, code reviews
5. **Deployment:** Package security, code signing

---

## App Store Review & Publishing

- Google: Focus on policy, design, automation
- Apple: Focus on security, privacy, design; manual review

---

## Tools for Mobile Penetration Testing

- **Static analysis**: Code review, MobSF, JADX, apktool, otool
- **Dynamic analysis**: Emulator, MobSF, Drozer, Frida, Burp Suite, Wireshark
- **Reverse engineering**: Decompile, patch, analyze

---

## Threat Modeling

- Identify architecture, data flows, trust boundaries
- Use STRIDE (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Privilege Escalation)
- Rank risks, prioritize remediation

---

## Attack Surface Mapping

- Find entry points: UI, APIs, file storage, logs, 3rd party libs

---

## OWASP Mobile Top 10 (2023)

| ID  | Vulnerability                       |
|-----|-------------------------------------|
| M1  | Improper Credential Usage           |
| M2  | Inadequate Supply Chain Security    |
| M3  | Insecure AuthN / AuthZ              |
| M4  | Insufficient Input/Output Validation|
| M5  | Insecure Communication              |
| M6  | Inadequate Privacy Controls         |
| M7  | Insufficient Binary Protections     |
| M8  | Security Misconfiguration           |
| M9  | Insecure Data Storage               |
| M10 | Insufficient Cryptography           |

---

## Examples & Attack Scenarios

### M1: Improper Credential Usage

- **Hardcoded API Keys/Secrets**  
    - Decompile app → extract → abuse APIs  
    - _Mitigation_: Don't hardcode secrets, rotate keys.

- **Weak Password Policies/Brute-forcing**
    - No lockout/rate-limit → automated attacks

- **Credentials in Local Storage**
    - Unencrypted prefs, stolen on device access

- **Insecure OAuth**
    - Leaked tokens via implicit flow, MitM

- **Debug Logging credentials**
    - Logging passwords/tokens; adb/console log leaks

---

### M2: Inadequate Supply Chain Security

- Tampered third-party SDKs or open-source deps
- Compromised build servers, dependency confusion attacks
- Unverified app updates

---

### M3: Insecure Authentication/Authorization

- Debug code in production
- Token replay (no expiry)
- Weak biometrics
- Poor role-based access control
- Credentials in logs

---

### M4: Insufficient Input/Output Validation

- SQL Injection from unsanitized inputs
- XSS in chat apps
- Remote code execution through uploads
- Buffer overflows
- Directory traversal

---

### M5: Insecure Communication

- HTTP instead of HTTPS, weak TLS config
- Certificate pinning bypass
- Information leaks in push notifications

---

### M6: Inadequate Privacy Controls

- Leaked location/contact data, excessive analytics tracking
- Sensitive data in logs
- Public/exposed cloud storage buckets

---

### M7: Insufficient Binary Protection

- No obfuscation: easy reverse engineering, API key theft
- No integrity checks: patching, malware injection
- Debugging enabled: extract secrets with IDA/Ghidra

---

### M8: Security Misconfiguration

- Debug features in production
- Excessive permissions
- Cloud storage misconfigs
- Default credentials
- Exposed internal API endpoints

---

### M9: Insecure Data Storage

- Plaintext credentials/tokens in prefs, SQLite, files
- Caching sensitive data in temp files
- Insecure cloud backup
- Data in logs

---

### M10: Insufficient Cryptography

- Weak/hardcoded keys, deprecated algorithms
- Keys stored in source
- No crypto in transit

---

## Recon: Penetration Testing Steps

1. Understand the app (functionality, data flows)
2. Static analysis (extract binary, manifest/plist)
3. Dynamic analysis (traffic interception, runtime behavior)
4. External recon (app store, 3rd party integrations, search engine dorks)
5. Map the attack surface

---

## Android Static Analysis

- Look for: hardcoded secrets, insecure logging, insecure storage, weak crypto, unprotected components, WebView vulns, insecure communication, code reflection.

### Examples


---

## Insecure Storage Patterns

- SharedPreferences (unencrypted)
- External storage (public world-readable)
- SQLite DBs (unencrypted)
- Plaintext logs

---

## Weak Cryptography in Code

- Hardcoded AES keys
- DES/MD5/RC4
- ECB mode


---

## WebView Vulnerabilities

- `setJavaScriptEnabled(true)`
- user-controlled URL in `loadUrl()`
- `addJavascriptInterface` risks

---

## iOS Static Analysis

- Hardcoded keys, insecure UserDefaults, weak crypto, unvalidated URL schemes, insecure logging/Keychain, jailbreak detection bypass.


---

## Threat Modeling: STRIDE

- _Spoofing_: Faked login, OAuth abuse
- _Tampering_: APK / IPA modification
- _Repudiation_: No/lax auditing
- _Information disclosure_: API, log, storage leaks
- _DoS_: App/network resource exhaustion
- _Privilege escalation_: App/OS permission errors

---

## Reporting

### Structure

- Executive Summary
- Scope and Methodology
- Findings & Risk Ratings (OWASP/CWE, PoC, screenshots)
- Remediation Recommendations
- Appendices (evidence, data, tools)

- Risks: use CVSS or similar scoring

---

## General Best Practices

- Avoid hardcoded secrets/keys
- Encrypt everything in storage/transit
- Use strong, proven crypto
- Secure app distribution and updates
- Minimize/explain permissions
- Harden binaries (obfuscation, integrity checks)
- Keep dependencies updated
- Regular code & security reviews
- User education & clear consent
- Monitor app analytics/logs for abuse

---

## Summary

Mobile app security requires defense-in-depth: robust code, strong crypto, minimal permissions, regular testing, and good reporting. The attack surface is broad and the consequences are high; prioritize security from the first line of code.


