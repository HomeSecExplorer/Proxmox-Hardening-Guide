# Proxmox Hardening Guide

[![CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-green.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/HomeSecExplorer/Proxmox-Hardening-Guide?color=blue)](https://github.com/HomeSecExplorer/Proxmox-Hardening-Guide/releases)
[![Issues](https://img.shields.io/github/issues/HomeSecExplorer/Proxmox-Hardening-Guide?color=blue)](https://github.com/HomeSecExplorer/Proxmox-Hardening-Guide/issues)

[![Github-sponsors](https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA)](https://github.com/sponsors/HomeSecExplorer)

[![PVE9](https://img.shields.io/badge/PVE9-orange)](docs/pve9-hardening-guide.md)
[![PBS4](https://img.shields.io/badge/PBS4-orange)](docs/pbs4-hardening-guide.md)
[![PVE8](https://img.shields.io/badge/PVE8-orange)](docs/pve8-hardening-guide.md)
[![PBS3](https://img.shields.io/badge/PBS3-orange)](docs/pbs3-hardening-guide.md)

The **Proxmox Hardening Guide** project provides structured, actionable recommendations to secure
**Proxmox Virtual Environment (PVE 9.x & 8.x)** and **Proxmox Backup Server (PBS 4.x & 3.x)**.

These guides are designed for system administrators and security engineers who need
**step-by-step hardening instructions, compliance alignment with the CIS Debian Benchmark, and best practices for enterprise and homelab deployments**.

They extend the industry-recognized *CIS Debian Benchmark* with Proxmox-specific security tasks, practical examples, and real-world best practices.

[Available Hardening Guides](#available-hardening-guides)

---

## Project Status

> [!WARNING]
> This project is under active development and some controls are still being validated.\
> Your feedback, testing results, and contributions are strongly encouraged to help improve accuracy, completeness, and reliability.

### ToDos

Some steps are flagged with “Controls have **not** yet been validated.” If you have a lab environment, I’d love your help testing these and sharing what you find (successes and issues alike). Thank you!

#### PVE 9 guide - items to validate

- 1.1.5 - Enable Full-Disk Encryption
- 1.2.1.1 - Enable UEFI Secure Boot
- 1.2.1.2 - Kernel Lockdown (Integrity Mode)
- 1.3 - SDN
- 5.3.2 - Rootkit Detection

#### PBS 4 guide - items to validate

- 1.1.5 - Enable Full-Disk Encryption (including Ceph OSD impact/performance validation)
- 1.2.1.1 - Enable UEFI Secure Boot
- 1.2.1.2 - Kernel Lockdown (Integrity Mode)
- 1.2.4 - ZFS datasets
- 1.2.5 - SMB/CIFS mount
- 5.3.2 - Rootkit Detection

#### PVE 8 guide - items to validate

- 1.1.2 - Apply Debian 12 CIS Level 2
- 1.1.4 - ssh-audit: step 6 (connection rate throttling) on clusters
- 1.1.5 - Enable Full-Disk Encryption
- 1.2.1.1 - Enable UEFI Secure Boot
- 1.2.1.2 - Kernel Lockdown (Integrity Mode)
- 1.3 - SDN
- 3.5 - Ceph Messenger Encryption (In-Flight)
- 5.3.2 - Rootkit Detection

#### PBS 3 guide - items to validate

- 1.1.2 - Apply Debian 12 CIS Level 2
- 1.1.5 - Enable Full-Disk Encryption (including Ceph OSD impact/performance validation)
- 1.2.1.1 - Enable UEFI Secure Boot
- 1.2.1.2 - Kernel Lockdown (Integrity Mode)
- 1.2.4 - ZFS datasets
- 1.2.5 - SMB/CIFS mount
- 5.1.2 - Auditd for /etc/proxmox-backup
- 5.3.2 - Rootkit Detection

---

## Available Hardening Guides

Choose the guide for your version: PVE 9 hardening, PBS 4 hardening, PVE 8 hardening, or PBS 3 hardening:

| Guide | Product | Guide Version | Path |
|-------|---------|---------|------|
| **PVE 9** | Proxmox Virtual Environment 9.x | 0.9.1 - 12 January 2026 | [`docs/pve9-hardening-guide.md`](docs/pve9-hardening-guide.md) |
| **PBS 4** | Proxmox Backup Server 4.x | 0.9.1 - 12 January 2026 | [`docs/pbs4-hardening-guide.md`](docs/pbs4-hardening-guide.md) |
| **PVE 8** | Proxmox Virtual Environment 8.x | 0.9.4 - 12 January 2026 | [`docs/pve8-hardening-guide.md`](docs/pve8-hardening-guide.md) |
| **PBS 3** | Proxmox Backup Server 3.x | 0.9.4 - 12 January 2026 | [`docs/pbs3-hardening-guide.md`](docs/pbs3-hardening-guide.md) |

**Key Benefits:**

- **Security Best Practices for PVE and PBS** - aligned with the *CIS Debian Benchmark* and adapted to virtualization and backup environments.
- **Step-by-Step Hardening Guides** - clear instructions for system administrators, security engineers, and auditors.
- **Comprehensive Proxmox Security Coverage** - includes configuration, datastore verification, automated backups, encryption, and disaster recovery testing.

---

## Safety first

Before you change anything:

- Create a recent backup or snapshot of the node and critical VMs or containers.
- Schedule a maintenance window so you can reboot if needed.
- Ensure you have out-of-band access (IPMI, iKVM, physical console).
- Record your current settings so you can restore them if required.

## Quick Start

Clone the repository and open the guide you need:

```bash
git clone https://github.com/HomeSecExplorer/proxmox-hardening-guide.git
cd proxmox-hardening-guide/docs
```

## How to use these guides

1. **Start in a lab/staging node first** (or a single non-critical host).
2. Ensure you have **working backups** and **out-of-band/console access** before changing SSH, firewall, boot, or storage settings.
3. Apply controls **incrementally**:
   - Do **Level 1** first (lowest risk, highest baseline value).
   - Move to **Level 2** only when you understand the operational impact.
   - Apply Level 3 **only when needed**
4. After each change, **validate service health** (GUI access, SSH, storage, cluster status, backups, VM migration) and keep a rollback path.
5. Use the **Execution Status** checkboxes to track what’s applied per host, and record deviations with a short note.

---

## Contributing

Community collaboration is highly welcome! Please see the detailed instructions in [`CONTRIBUTING.md`](CONTRIBUTING.md)

- Found an issue or have feedback? Open an Issue.
- Want to contribute improvements? Fork the repository and submit your pull request against the dev branch.

---

## Disclaimer & Terms of Use

> [!WARNING]
> ⚠️ **AS‑IS, NO WARRANTY**.

By using these guides, you agree to:

1. **Responsibility** - You must test and validate each recommendation yourself before applying it.
2. **No Liability** - The authors and contributors are **not liable** for any direct, indirect, or consequential damages arising from the use of this guidance.
3. **License** - All content is licensed under **CC BY 4.0** (see [`LICENSE`](LICENSE)).  
4. **Community Techniques** - Some recommended practices are community-driven and **not officially supported** by Proxmox GmbH. Use at your own risk.
