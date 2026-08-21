# 🛡️ Active Directory Attack Detection & Mitigation

![Focus](https://img.shields.io/badge/Focus-Blue%20Team-blue)
![Platform](https://img.shields.io/badge/Platform-Active%20Directory-informational)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange)
![Detections](https://img.shields.io/badge/Sigma%20Rules-Included-brightgreen)

A curated, blue-team-focused knowledge base of **Active Directory attack techniques** — how they work, how to detect them, and how to stop them. Each attack page follows a consistent structure so you can jump straight to what you need: the mechanics, ready-to-use Sigma rules, and hardening steps.

---

## 📖 What's Inside

Every attack file in this repo follows the same five-part structure:

| Section | What it covers |
|---|---|
| 📌 **1. Attack Overview** | MITRE ATT&CK mapping, what the attack is, why it works (with flow diagram), attacker goals, tools used |
| 🔎 **2. Detection** | Relevant Windows Event IDs, log fields, and behavioral indicators |
| 🧩 **3. Sigma Rule** | Ready-to-deploy Sigma detection rules in YAML |
| 🛡️ **4. Mitigation** | Concrete hardening steps to prevent or reduce the attack surface |
| 📚 **5. Resources** | External references for further reading |

Each page also opens with a **Quick Reference** table for fast triage — MITRE ID, key Event IDs, indicators, tools, and mitigations at a glance.

---

## 📂 Attack Index

| Attack | Tactic | MITRE ID | Sigma Rule |
|---|---|---|---|
| 🎫 [Kerberoasting](AD%20Detection%20&%20Mitigation/Kerberoasting%20Attack.md) | Credential Access | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | ✅ |
| 🎟️ [AS-REP Roasting](AD%20Detection%20&%20Mitigation/Authentication%20Server%20Response%20(AS-REP)%20Roasting.md) | Credential Access | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | ✅ |

---
## 🎯 Who This Is For

This repo is built for **blue teams, detection engineers, and SOC analysts** who need to:

- Understand how common AD attacks actually work under the hood
- Deploy practical, tested Sigma detection rules
- Harden Active Directory against credential theft and privilege escalation
- Map detections back to MITRE ATT&CK for coverage tracking

#### 🤝 Contributing Contributions are welcome. To add a new attack page:


## ⚖️ License
This project is intended for defensive, educational, and blue-team purposes only.
