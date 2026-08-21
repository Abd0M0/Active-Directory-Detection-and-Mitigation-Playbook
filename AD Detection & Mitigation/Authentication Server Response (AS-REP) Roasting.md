# 🎟️ AS-REP Roasting

## 📌 1. Attack Overview

### 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| 🔑 Credential Access | Steal or Forge Kerberos Tickets: AS-REP Roasting | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| 🔍 Discovery | Account Discovery: Domain Account | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) |
| ↔️ Lateral Movement | Use Alternate Authentication Material | [T1550](https://attack.mitre.org/techniques/T1550/) |

### 🎟️ What is AS-REP Roasting?

**AS-REP Roasting** is an Active Directory attack that targets accounts with the **"Do not require Kerberos pre-authentication"** flag (`DONT_REQ_PREAUTH`) set. Unlike Kerberoasting, the attacker doesn't even need valid credentials to trigger it — they only need to know (or guess) a username. Because pre-authentication is disabled, the Domain Controller hands back an encrypted **AS-REP** blob without ever verifying the requester actually knows the account's password. That blob is encrypted with the target user's password hash and can be cracked offline.

![AS-REP Roasting Attack Flow](../Images/AS-REP%20Roasting%20Attack.png)

### ⚙️ Why does it work? 

**Normal Kerberos Authentication (with Pre-Authentication):**

1. 📨 **User sends AS-REQ (Authentication Request):** It includes a timestamp encrypted with the user's password hash. <br> This step — **pre-authentication** — proves the user actually knows their password.
3. 🔍 **Domain Controller (KDC/AS) verifies:** If the timestamp decrypts correctly, the DC knows the user is legitimate, and sends back the **AS-REP** (containing a TGT and session key).

 ### 🔴 When Pre-Authentication is Disabled (Vulnerable Case):

If a user account has **"Do not require Kerberos pre-authentication"** enabled:

1. 🎭 **Attacker sends AS-REQ** for that account — no password required, and it can target any domain user, privileged or not.
2. 📩 **DC responds with AS-REP immediately** — no timestamp check is performed. The AS-REP contains data encrypted with the target user's password hash.
3. 🎯 **Attacker captures the AS-REP.**
4. 🔨 **Offline cracking:** The attacker cracks the AS-REP blob using Hashcat, John, Rubeus, or Impacket. If successful, they recover the user's plaintext password.

The key difference from Kerberoasting: **AS-REP Roasting requires no valid domain credentials at all** — just a username — making it viable even before an attacker has any foothold.

### 🎯 What does the attacker want?

- 🔓 Works against **any account** with "no pre-auth" set — user, service, or admin.
- 📈 If the cracked account has high privileges (Domain Admin, Backup Operator, service account), it leads to **full domain compromise**.
- ⬆️ **Privilege escalation** — if the cracked account has elevated rights, the attacker escalates directly.
- ↔️ Even a low-privileged cracked account still gives the attacker a **valid credential** to move laterally and continue the attack chain.

### 🛠️ Tools Adversaries Use

| Tool | Purpose |
|---|---|
| 🐍 **Impacket (GetNPUsers.py)** | Enumerates accounts with `DONT_REQ_PREAUTH` set and requests AS-REP blobs for them. |
| 🗡️ **Rubeus** | Can enumerate and request AS-REP tickets for no-preauth accounts (`asreproast` module). |
| 🔨 **Hashcat** | Offline cracking of captured AS-REP hashes. |
| 🔓 **John the Ripper** | Alternative offline cracker for AS-REP hash material. |

---

## 🔎 2. Detection

### 📜 Event ID 4768 — TGT Request
- **Source:** Domain Controllers
- **Why it matters:** Always generated when a TGT is requested — including the AS-REQ/AS-REP exchange abused by AS-REP Roasting.
- **Detection idea:**
  - Look for multiple 4768 events in a short time window for accounts flagged with no pre-auth.
  - Correlate with 4625 to determine whether the request came from a valid or invalid user context.

### 🚫 Event ID 4625 — Failed Logon
- **Source:** Domain Controllers
- **Why it matters:** If an attacker attempts AS-REP Roasting without valid credentials, the DC logs a failed logon — even though the AS-REP ticket is still returned.
- **Detection idea:**
  - Correlate 4625 with 4768 (TGT requests). 4625 + 4768 for the same account in a short window is a strong AS-REP Roasting indicator.

### 📝 Event IDs 4738 & 5136 — User Account Changed
- **Source:** Domain Controllers
- **Why it matters:** An attacker with sufficient rights may disable pre-auth (`DONT_REQ_PREAUTH`) on an account, roast it, then re-enable pre-auth afterward to hide their tracks.
- **Detection idea:**
  - Monitor for changes to the Kerberos pre-authentication flag on accounts.
  - Specifically watch `UserAccountControl` changes involving "Do not require Kerberos pre-authentication."

### 📋 Summary

| Signal | Meaning |
|---|---|
| 🟠 4768 (repeated, short window) | Possible AS-REP enumeration against no-preauth accounts |
| 🔴 4625 + 4768 (same account, correlated) | Suspicious AS-REP Roasting attempt |
| 🟠 4738 / 5136 (pre-auth flag toggle) | Possible attacker hiding tracks after roasting |
| 🟢 No accounts with `DONT_REQ_PREAUTH` | Attack surface eliminated |

---

## 🧩 3. Sigma Rule

```yaml
title: Possible AS-REP Roasting Enumeration
id: 9c2e4f7a-6b1d-4c8e-a3f5-7d9b1e4c6a8f
status: experimental
description: >
  Detects a pattern of Kerberos AS-REQ/TGT requests (Event ID 4768) paired
  with failed logon events (Event ID 4625) for the same account, which is
  characteristic of AS-REP Roasting attempts against accounts with Kerberos
  pre-authentication disabled.
references:
  - https://attack.mitre.org/techniques/T1558/004/
author: '<Your Name / Team>'
date: 2026-08-20
tags:
  - attack.credential-access
  - attack.t1558.004
logsource:
  product: windows
  service: security
  definition: 'Requires auditing of Kerberos Authentication Service and Logon events to be enabled'
detection:
  selection_tgt:
    EventID: 4768
    PreAuthType: '0'
  selection_failed_logon:
    EventID: 4625
  timeframe: 5m
  condition: selection_tgt and selection_failed_logon | count(TargetUserName) by TargetUserName > 1
falsepositives:
  - Legitimate accounts intentionally configured without pre-auth for legacy application compatibility
  - Clock skew or misconfigured clients causing benign pre-auth failures
level: high
```
```yaml
title: TGT Request for Account With Pre-Authentication Disabled
id: 1e5d8a3c-4f7b-4a2e-9c1d-6b8f3a5e7c9d
status: experimental
description: >
  Detects Event ID 4768 TGT requests where PreAuthType indicates no
  pre-authentication was used, which is required for AS-REP Roasting to
  succeed. Should be correlated against a known-good baseline of accounts
  intentionally configured this way.
references:
  - https://attack.mitre.org/techniques/T1558/004/
author: '<Your Name / Team>'
date: 2026-08-20
tags:
  - attack.credential-access
  - attack.t1558.004
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
  condition: selection
falsepositives:
  - Known, intentionally-configured no-preauth service accounts (should be baselined and excluded)
level: medium
```

> ℹ️ **Note:** Field names (`PreAuthType`, `TargetUserName`) should be mapped to your SIEM's log field-naming convention (e.g., Splunk CIM, Elastic ECS) at deployment time. Maintain a baseline list of accounts intentionally configured without pre-auth to reduce false positives.

---

## 🛡️ 4. Mitigation

1. 🔐 **Require Kerberos Pre-Authentication**
   - Audit AD for accounts with the `DONT_REQ_PREAUTH` flag set:
     ```powershell
     Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
     ```
   - Remove that flag unless absolutely required for a specific legacy application.

2. 🪜 **If You Must Keep No-Pre-Auth Accounts**
   - Apply the principle of least privilege:
     - Don't place them in privileged groups (Domain Admins, Enterprise Admins, etc.).
     - Restrict them to only what's strictly needed.
   - Enforce long, complex, unique passwords:
     - Service accounts: **≥ 30 characters**.
     - User accounts: **≥ 15 characters**.
     - Rotate regularly and store in a password vault.

3. 🧱 **General Hardening**
   - Monitor for abnormal AS-REQ traffic — Event ID 4768 can reveal suspicious requests.
   - Use **Managed Service Accounts (gMSA)** instead of static service accounts.
   - Regularly review accounts flagged with special properties (no pre-auth, unconstrained delegation, etc.).

---

## 📚 5. Resources

- 🔗 [MITRE ATT&CK – T1558.004 AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)
- 🔗 [Impacket – GetNPUsers.py](https://github.com/fortra/impacket)
