# Proxmox Hardening Guide

![CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-green.svg)

The **Proxmox Hardening Guide** project provides structured, actionable recommendations to secure
**Proxmox Virtual Environment (PVE 8.x)** and **Proxmox Backup Server (PBS 3.x)**.

These guides are designed for system administrators and security engineers who need
**step-by-step hardening instructions, compliance alignment with the CIS Debian 12 Benchmark, and best practices for enterprise and homelab deployments**.

They extend the industry-recognized *CIS Debian 12 Benchmark* with Proxmox-specific security tasks, practical examples, and real-world best practices.

[Available Hardening Guides](#available-hardening-guides)

---

## Project Status

> [!WARNING]
> This project is under active development and some controls are still being validated.\
> Your feedback, testing results, and contributions are strongly encouraged to help improve accuracy, completeness, and reliability.

**ToDos**

Some steps are flagged with “Controls have **not** yet been validated.” If you have a lab environment, I’d love your help testing these and sharing what you find (successes and issues alike). Thank you!

**PVE 8 guide - items to validate**

- 1.1.2 - Apply Debian 12 CIS Level 2
- 1.1.4 - ssh-audit: step 6 (connection rate throttling) on clusters
- 1.1.5 - Enable Full-Disk Encryption
- 1.2.1.1 - Enable UEFI Secure Boot
- 1.2.1.2 - Kernel Lockdown (Integrity Mode)
- 1.3 - SDN
- 3.5 - Ceph Messenger Encryption (In-Flight)
- 5.3.2 - Rootkit Detection

**PBS 3 guide - items to validate**

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

| Guide | Product | Guide Version | Path |
|-------|---------|---------|------|
| **PVE 8** | Proxmox Virtual Environment 8.x | 0.9.2 - 05 October 2025 | [`docs/pve8-hardening-guide.md`](docs/pve8-hardening-guide.md) |
| **PBS 3** | Proxmox Backup Server 3.x | 0.9.2 - 05 October 2025 | [`docs/pbs3-hardening-guide.md`](docs/pbs3-hardening-guide.md) |

**Key Benefits:**

- **Security Best Practices for PVE and PBS** - aligned with the *CIS Debian 12 Benchmark* and adapted to virtualization and backup environments.
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
