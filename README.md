# VEXT-CERT — Moroccan DNSSI 2023 Linux Hardening & Audit Suite

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/vext-dnssi-hardener/badge)](https://www.bestpractices.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Compliance](https://img.shields.io/badge/DNSSI%202023-DGSSI%20Loi%2005--20-blue)](https://vext.ma/trust)
[![RFC 2350](https://img.shields.io/badge/CSIRT-VEXT--CERT-purple)](https://vext.ma/.well-known/rfc2350.txt)

An open-source, automated cybersecurity hardening engine and compliance audit suite conforming to the **Moroccan Directive Nationale de la Sécurité des Systèmes d'Information (DNSSI 2023, Chapters 6 & 7)** and **ANSSI BP-028 (Niveau Renforcé)**.

Maintained by **VEXT-CERT** (Casablanca, Kingdom of Morocco · `https://vext.ma`).

---

## Capabilities

* **Automated OS Hardening:** 25 statutory controls across kernel sysctl parameters, SSH daemon, PAM password quality, file system permissions, and auditd rules.
* **Dual Execution Modes:**
  * **Audit Mode (Default):** Non-destructive inspection generating a scored compliance report (0–100%) against DNSSI requirements without modifying system files.
  * **Remediate Mode (`--remediate`):** Automatically applies hardening configurations with timestamped rollbacks in `/var/backups/vext-dnssi-*`.
* **Multi-Format Integration:**
  * Standalone Bash script (`vext_dnssi_linux_hardener.sh`).
  * Ansible Playbook (`dnssi_hardener_playbook.yml`).
  * SCAP 1.3 / OpenSCAP benchmark profile (`dnssi_scap_profile.xml`).

---

## Quick Start

### 1. Run an Audit (Read-Only)
```bash
sudo ./vext_dnssi_linux_hardener.sh
# Or fetch and run directly:
curl -sSL https://raw.githubusercontent.com/abdnaouri/vext-dnssi-hardener/main/vext_dnssi_linux_hardener.sh | sudo bash
```

### 2. Apply Hardening Controls
```bash
sudo ./vext_dnssi_linux_hardener.sh --remediate
```

### 3. Run with Ansible
```bash
ansible-playbook -i inventory.ini dnssi_hardener_playbook.yml
```

---

## Standards Alignment

| Standard | Scope | Target Systems |
| :--- | :--- | :--- |
| **Moroccan Law n° 05-20 (Art. 6, 8, 12, 19)** | Critical National Infrastructure & Sensitive Information Systems | Moroccan Banking, Telecom, Energy, Public Administration |
| **DGSSI DNSSI 2023 (Ch. 6 & 7)** | Logical Security, System Architecture & Operational Hardening | Linux Servers (Ubuntu 20.04/22.04/24.04, Debian 11/12, RHEL 8/9) |
| **ANSSI BP-028** | Recommandations de sécurité relatives à un système GNU/Linux | Configuration de base et niveau renforcé |

---

## Security & Vulnerability Reporting

Security disclosures for this project are handled by **VEXT-CERT**:
* **Email:** `cert@vext.ma`
* **PGP Key:** `https://vext.ma/pgp-key.txt`
* **Security Policy:** `https://vext.ma/.well-known/security.txt`
* **CSIRT Charter (RFC 2350):** `https://vext.ma/.well-known/rfc2350.txt`

---

## License

This project is licensed under the [MIT License](LICENSE).
