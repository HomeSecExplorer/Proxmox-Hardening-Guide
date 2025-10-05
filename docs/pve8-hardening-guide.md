# Proxmox VE 8.x Hardening Guide

### Version 0.9.2 - October 05, 2025

### Author: [HomeSecExplorer](https://github.com/HomeSecExplorer)

![HomeSecExplorer_Banner](https://github.com/HomeSecExplorer/HomeSecExplorer/blob/main/assets/banner.png?raw=true)

---

## Terms of Use

This guide is provided **“as is,” without warranty of any kind**, whether express or implied.
The author(s) and the [HomeSecExplorer Proxmox Hardening Guide](https://github.com/HomeSecExplorer/Proxmox-Hardening-Guide) project make
**no guarantees** regarding completeness, accuracy, or fitness for any particular purpose. By using this guide, you agree that:

1. **Responsibility**\
   You remain solely responsible for evaluating, testing, and validating every recommendation in your environment.
   Any security control that introduces operational risk **must** be reviewed, adjusted, or rejected by you.
2. **No Liability**\
   The author(s) and contributors are **not liable** for direct, indirect, incidental, or consequential damages arising from the use of this guide, even if advised of the possibility of such damages.
3. **Attribution & Licensing**\
   This guide is released under the **CC BY 4.0 license** (see [../LICENSE](../LICENSE)). You may copy, modify, and distribute the content provided you retain
   attribution to the original author(s) **and** link back to the project repository.
4. **No Endorsement**\
   References to third-party products or services do **not** imply an endorsement. All trademarks belong to their respective owners.
5. **Community Contributions**\
   Improvements are welcome! Please open an **issue** on the [Proxmox Hardening Guide repository](https://github.com/HomeSecExplorer/Proxmox-Hardening-Guide) to discuss changes. After consensus is reached, submit a **pull request** for review.
6. **Community Techniques**\
   Some procedures in this guide are **community best-effort methods** and **not officially supported** by Proxmox GmbH.
   Evaluate, test, and maintain these at your own risk; do not expect vendor support for issues arising from their use.

By continuing to use this document you acknowledge that you have read, understood, and agreed to these terms.

---

## Table of Contents

1. [Terms of Use](#termsofuse)
2. [Overview](#overview)
   - [Usage Information](#usage-information)
   - [Safe Remediation Workflow](#safe-remediation-workflow)
   - [Target Technology Details](#target-technology-details)
   - [Assumptions](#assumptions)
   - [Installation Note](#installation-note)
   - [Pre-deployment Checklist](#pre-deployment-checklist)
   - [Typographical Conventions](#typographical-conventions)
   - [References](#references)
   - [Definitions & Abbreviations](#definitions--abbreviations)
   - [System Inventory Template](#system-inventory-template)
   - [Hardening Level Selection](#hardening-level-selection)
3. [Recommendations](#recommendations)
   - [1 Initial Setup](#1-initial-setup)
      - [1.1 Base OS](#11-base-os)
         - [1.1.1 Apply Debian 12 CIS Level 1](#111-apply-debian-12-cis-level-1)
         - [1.1.2 Apply Debian 12 CIS Level 2](#112-apply-debian-12-cis-level-2)
         - [1.1.3 Configure Automatic Security Updates](#113-configure-automatic-security-updates)
         - [1.1.4 Apply ssh-audit Hardening Profile](#114-apply-ssh-audit-hardening-profile)
         - [1.1.5 Enable Full-Disk Encryption](#115-enable-full-disk-encryption)
         - [1.1.6 Dedicated Filesystem for /var/lib/vz](#116-dedicated-filesystem-for-varlibvz)
      - [1.2 Base PVE](#12-base-pve)
         - [1.2.1 Secure Boot](#121-secure-boot)
            - [1.2.1.1 Enable UEFI Secure Boot](#1211-enable-uefi-secure-boot)
            - [1.2.1.2 Kernel Lockdown (Integrity Mode)](#1212-kernel-lockdown-integrity-mode)
         - [1.2.2 Network Separation](#122-network-separation)
         - [1.2.3 Maintain a Valid Proxmox Subscription](#123-maintain-a-valid-proxmox-subscription)
         - [1.2.4 Enable the PVE Firewall](#124-enable-the-pve-firewall)
         - [1.2.5 PVE Firewall - Default FORWARD Policy “DROP”](#125-pve-firewall---default-forward-policy-drop)
         - [1.2.6 Review/Configure Kernel Samepage Merging (KSM)](#126-reviewconfigure-kernel-samepage-merging-ksm)
         - [1.2.7 Avoid LXC - Run Container Platforms Inside VMs](#127-avoid-lxc---run-container-platforms-inside-vms)
         - [1.2.8 Unprivileged Containers by Default](#128-unprivileged-containers-by-default)
         - [1.3 SDN Hardening](#13-sdn-hardening)
            - [1.3.1 SDN Baseline (Zones, VNets, Isolation)](#131-sdn-baseline-zones-vnets-isolation)
            - [1.3.2 SDN Firewall Defaults (VNet‑level)](#132-sdn-firewall-defaults-vnetlevel)
            - [1.3.3 DHCP/RA Guard on VNets](#133-dhcpra-guard-on-vnets)
            - [1.3.4 SDN Overlay Transport Hardening (VXLAN)](#134-sdn-overlay-transport-hardening-vxlan)
            - [1.3.5 EVPN/BGP Controller Hardening](#135-evpnbgp-controller-hardening)
            - [1.3.6 Bridge & Kernel Settings for SDN](#136-bridge--kernel-settings-for-sdn)
   - [2 GUI Access & ACLs](#2-gui-access--acls)
      - [2.1 Users](#21-users)
         - [2.1.1 Use Personalized Accounts](#211-use-personalized-accounts)
         - [2.1.2 Grant Least Privilege](#212-grant-least-privilege)
         - [2.1.3 Enable 2FA](#213-enable-2fa)
         - [2.1.4 root emergency access](#214-break-glass-emergency-access)
      - [2.2 API Tokens](#22-api-tokens)
         - [2.2.1 Use Scoped API Tokens](#221-use-scoped-api-tokens)
         - [2.2.2 Grant Least Privilege to Tokens](#222-grant-least-privilege-to-tokens)
         - [2.2.3 Store Tokens Securely](#223-store-tokens-securely)
         - [2.2.4 Rotate Tokens Regularly](#224-rotate-tokens-regularly)
      - [2.3 GUI](#23-gui)
         - [2.3.1 Install Trusted Certificates](#231-install-trusted-certificates)
         - [2.3.2 Automate Certificate Renewal](#232-automate-certificate-renewal)
         - [2.3.3 Protect the GUI with Fail2Ban](#233-protect-the-gui-with-fail2ban)
   - [3 Cluster Protections](#3-cluster-protections)
      - [3.1 Provide Redundant Corosync Links](#31-provide-redundant-corosync-links)
      - [3.2 Secure Inter-Node Communication](#32-secure-inter-node-communication)
      - [3.3 Ceph pool sizing and failure domains](#33-ceph-pool-sizing-and-failure-domains)
      - [3.4 Ceph OSD Encryption](#34-ceph-osd-encryption)
      - [3.5 Ceph Messenger Encryption (In-Flight)](#35-ceph-messenger-encryption-in-flight)
   - [4 Backup & Disaster Recovery](#4-backup--disaster-recovery)
      - [4.1 Enforce 3-2-1 Backup Strategy](#41-enforce-3-2-1-backup-strategy)
      - [4.2 Backup Host Configuration](#42-backup-host-configuration)
         - [4.2.1 Backup Host Configuration](#421-backup-host-configuration)
         - [4.2.2 Encrypt Host Configuration Backups](#422-encrypt-host-configuration-backups)
      - [4.3 Automate Backups](#43-automate-backups)
      - [4.4 Encrypt Backups](#44-encrypt-backups)
      - [4.5 Notify on Failed Backup](#45-notify-on-failed-backup)
      - [4.6 Document and Test Restores](#46-document-and-test-restores)
   - [5 Logging, Monitoring, Auditing & Documentation](#5-logging-monitoring-auditing--documentation)
      - [5.1 Logging](#51-logging)
         - [5.1.1 Centralized Logging](#511-centralized-logging)
         - [5.1.2 Auditd for /etc/pve](#512-auditd-for-etcpve)
      - [5.2 Monitoring](#52-monitoring)
         - [5.2.1 Centralized Metrics](#521-centralized-metrics)
         - [5.2.2 Alerting](#522-alerting)
      - [5.3 Auditing](#53-auditing)
         - [5.3.1 System Audits](#531-system-audits)
         - [5.3.2 Rootkit Detection](#532-rootkit-detection)
      - [5.4 Documentation](#54-documentation)
4. [Exception Handling](#exception-handling)
5. [Appendices](#appendices)
   - [A. CIS Benchmark](#a-cis-benchmark)
   - [B. Example Ansible Snippets](#b-example-ansible-snippets)
   - [C. Recovery-Drill Checklist](#c-recovery-drill-checklist)
   - [D. Installation Checklist](#d-installation-checklists-host-and-guest)
6. [Change Notes](#change-notes)

---

## Overview

- **Scope:** All single-node and clustered Proxmox VE installations.
- **Audience:** System administrators, security engineers, and compliance auditors responsible for Proxmox VE deployments.

### Usage Information

This guide provides **prescriptive hardening guidance** for Proxmox VE 8.
It does **not** guarantee absolute security;
integrate it into a comprehensive cybersecurity program. Always approach changes with caution and follow a structured test-and-release process.

#### Safe Remediation Workflow

1. **Never** deploy changes directly to production.
2. Include the following gates:
   - **Inventory & Analysis** - Document the current configuration and dependencies.
   - **Impact Review** - Read the *Impact* subsection of each recommendation to identify side-effects.
   - **Lab Testing** - Apply changes to representative, non-production systems.
   - **Phased Deployment**
      1. Deploy to a limited pilot group.
      2. Monitor for at least one full business cycle.
      3. Resolve issues before a wider rollout.
   - **Gradual Rollout** - Expand in stages while continuously monitoring.

> [!NOTE]
> No single guide can cover every environment. If you discover conflicts or unexpected impacts, please open an issue on the project repository and share details.

### Target Technology Details

This guidance was developed and validated on **Proxmox VE 8** running on **Debian 12 “bookworm”** (x86-64).

#### Assumptions

- Commands are executed as **root** in the default shell.
- When using `sudo` or a different shell, confirm command syntax and environmental differences.

#### Installation Note

To satisfy several CIS Debian Benchmark controls (for example, partition layout), install **Debian 12 first** and then add the Proxmox VE repository **instead of** using the Proxmox ISO installer.

#### Pre-deployment Checklist

- Update system firmware and BIOS.
- Patch BMC / iDRAC / iLO management interfaces to the latest stable versions.

### Typographical Conventions

| Convention            | Meaning / Example Usage                                    |
| --------------------- | ---------------------------------------------------------- |
| `Multiline monospace` | Multi-line shell commands, scripts, or configuration files |
| `Inline monospace`    | Single commands, file paths, or UI menu items              |
| `<<placeholder>>`     | Text that **must** be replaced with an actual value        |
| *Italic text*         | Cross-references or external document titles               |
| **Bold text**         | **Warnings**, **Notes**, or emphasized terms               |

### References

- *CIS Debian Linux 12 Benchmark* - [CIS Debian](https://www.cisecurity.org/benchmark/debian_linux)
- *Proxmox VE Administration Guide* - [PVE admin guide](https://pve.proxmox.com/pve-docs/pve-admin-guide.html)
- *Debian Security Hardening Manual* - [Debian hardening](https://www.debian.org/doc/manuals/securing-debian-manual/index.en.html)

### Definitions & Abbreviations

| Term    | Definition                   |
| ------- | ---------------------------- |
| **PVE** | Proxmox Virtual Environment  |
| **CIS** | Center for Internet Security |
| **PBS** | Proxmox Backup Server        |
| **ACL** | Access Control List          |
| **2FA** | Two-Factor Authentication    |
| **OSD** | Object Storage Daemon (Ceph) |
| **ACME** | Automated Certificate Management Environment; protocol used by Let’s Encrypt |

### System Inventory Template

Maintain a current inventory of all PVE nodes.

Update the table after **every** hardware or configuration change.

| Hostname | IP Address | Role / Cluster | OS Version | CIS Level | Hardened On | Location | Notes           |
| -------- | ---------- | -------------- | ---------- | --------- | ----------- | -------- | --------------- |
| pve01    | 10.0.10.10 | Standalone     | Debian 12  | Level 2   | **No**      | DC1-R2   | No subscription |
| pvec1n01 | 10.0.10.11 | Cluster-1      | Debian 12  | Level 1   | Jul 2025    | DC1-R1   | Ceph-enabled    |
| pvec1n02 | 10.0.10.12 | Cluster-1      | Debian 12  | Level 1   | Jul 2025    | DC1-R1   | Ceph-enabled    |
| pvec1n03 | 10.0.10.13 | Cluster-1      | Debian 12  | Level 1   | Jul 2025    | DC1-R1   | Ceph-enabled    |

### Hardening Level Selection

| Level            | Summary                                                                      | When to Use                                             |
| ---------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------- |
| **1 - Baseline** | Minimal operational impact; mandatory for **all** PVE nodes.                 | Always                                                  |
| **2 - Enhanced** | Additional defense-in-depth controls. Evaluate each control for feasibility. | Regulated or high-security workloads                    |
| **3 - Advanced** | Maximum hardening; may introduce downtime or complexity.                     | Only when data sensitivity or threat model justifies it |

---

## Recommendations

### 1 Initial Setup

Apply these controls during or immediately after installation. Retrofitting them later can be disruptive.

#### 1.1 Base OS

---

##### 1.1.1 Apply Debian 12 CIS Level 1

**Level 1**

**Description**\
Establishes a secure **minimum** configuration for Debian 12 that balances security with stability. Controls include partitioning,
secure permissions, basic hardening of SSH, and kernel parameter tuning.

**Measures**

- Apply **all** remediations in the *CIS Debian 12 Benchmark Level 1 - Server* profile.

> [!CAUTION]
> **CIS deviation:** Skip *CIS Debian 12 Benchmark* control § 5.1.20 (**Disable SSH root login**) on PVE clusters and apply the mitigations below instead.
> **PVE clusters rely on `root@<node>` SSH for internal operations such as file replication and migrations.**
> Proxmox configures `PermitRootLogin yes` by default to support these workflows. Do **not** set `PermitRootLogin no`.
>
> **Recommended hardening:**
> - Prefer `PermitRootLogin prohibit-password` (allows root over SSH **keys** only).
> - Or keep `PermitRootLogin yes` **and** set `PasswordAuthentication no`.
> - Ensure `PubkeyAuthentication yes`.
> - Optionally restrict root SSH to management subnets using a Match block:
> ```
> Match Address <<10.0.10.0/24,10.0.20.0/24>>
>   PermitRootLogin yes
> Match all
>   PermitRootLogin no
> ```

> [!NOTE]
> Skip CIS Debian 12 Benchmark § 4 *Host-Based Firewall* **if** you enable the PVE Firewall in control [1.2.4](#124-enable-the-pve-firewall) of this guide.

> [!TIP]
> For Ansible automation, check out the *ansible-lockdown* role for Debian 12 CIS.  
> See [Appendix B](#b-example-ansible-snippets) for examples.
> [Debian 12 CIS Role](https://galaxy.ansible.com/ui/standalone/roles/ansible-lockdown/deb12_cis/)

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.1.2 Apply Debian 12 CIS Level 2

**Level 2**

**Description**\
Adds defense-in-depth measures, such as stricter file-permission policies and advanced kernel hardening, suitable for regulated or high-risk environments.
May impact certain workloads or third-party software.

**Measures**

- Apply **all** remediations in the *CIS Debian 12 Benchmark Level 2 - Server* profile after completing Level 1.
- Validate services such as Ceph, ZFS, and PBS in a **lab** before rolling out to production.

> [!WARNING]
> Controls have **not** yet been validated. Test thoroughly.

> [!CAUTION]
> **CIS deviation:** Skip *CIS Debian 12 Benchmark* § 5.1.8 (**DisableForwarding**) on PVE clusters and apply the mitigations below instead.
> On PVE clusters this **breaks secure live migration** (SSH‑tunneled QEMU migration) and other internal workflows that rely on TCP port forwarding.
> Do **not** enable `DisableForwarding yes` globally.
>
> **Safer alternatives:**
> - **Option A (recommended for most):** Leave `DisableForwarding no`, but harden individual features:
> ```
> X11Forwarding no
> AllowAgentForwarding no
> AllowStreamLocalForwarding no
> PermitTunnel no
> AllowTcpForwarding yes
> ```
> Restrict SSH access to management subnets with a `Match Address` block.
> - **Option B (strict with scoped exception):** Enable `DisableForwarding yes` **globally**, then allow TCP forwarding **only** for cluster‑internal root sessions coming from management networks:
> ```
> DisableForwarding yes
> Match User root Address <<10.0.10.0/24,10.0.20.0/24>>
>     DisableForwarding no
>     AllowTcpForwarding yes
>     X11Forwarding no
>     AllowAgentForwarding no
>     PermitTunnel no
> ```

> [!TIP]
> For Ansible automation, check out the *ansible-lockdown* role for Debian 12 CIS.  
> See [Appendix B](#b-example-ansible-snippets) for examples.
> [Debian 12 CIS Role](https://galaxy.ansible.com/ui/standalone/roles/ansible-lockdown/deb12_cis/)

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.1.3 Configure Automatic Security Updates

**Level 1**

**Description**\
Ensures critical Debian security patches are applied between maintenance windows to reduce the exposure window for known CVEs.

**Measures**

```bash
apt update && apt install unattended-upgrades apt-listchanges -y
```

Make sure the following lines are configured:

- `/etc/apt/apt.conf.d/20auto-upgrades`

   ```ini
   APT::Periodic::AutocleanInterval "7";
   APT::Periodic::Update-Package-Lists "1";
   APT::Periodic::Unattended-Upgrade "1";
   ```

- `/etc/apt/apt.conf.d/50unattended-upgrades`

   ```ini
   Unattended-Upgrade::Origins-Pattern {
     "origin=Debian,codename=${distro_codename},label=Debian";
     "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
     "origin=Debian,codename=${distro_codename},label=Debian-Security";
   };
   Unattended-Upgrade::Remove-Unused-Dependencies "true";
   Unattended-Upgrade::Automatic-Reboot "false";
   ```

- Enable service `systemctl enable unattended-upgrades`
- Monitor `/var/log/unattended-upgrades/unattended-upgrades.log` for failures.
- Optionally set mail notification in `/etc/apt/apt.conf.d/50unattended-upgrades`.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.1.4 Apply ssh-audit Hardening Profile

**Level 2**

**Description**\
Apply the recommended server and client-side hardening settings from the ssh-audit Debian 12 guides.
These settings remove legacy ciphers, MACs, and key-exchange algorithms that baseline CIS controls still permit.

**Measures**

1. Follow the *ssh-audit* [Debian 12 **server** guide](https://www.sshaudit.com/hardening_guides.html#debian_12).
2. Follow the *ssh-audit* [Debian 12 **client** guide](https://www.sshaudit.com/hardening_guides.html#debian_12_client).

> [!CAUTION]
> **Set root’s and other users SSH client to prefer RSA for cluster peers (to avoid host-key warnings).**
> Proxmox stores RSA host keys in `/etc/pve/nodes/*/ssh_known_hosts`.
> To keep PVE’s internal SSH stable while still using Ed25519 for external/admin access, configure `/root/.ssh/config` and `~/.ssh/config` on every node and for every relevant user as follows:
> ```sshconfig
> # === Cluster peers - use RSA host keys ===
> Host <<hse-pvecn* pve* *.cluster.local 10.0.10.* 10.0.20.*>>
>  HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256
>  PubkeyAcceptedAlgorithms rsa-sha2-512,rsa-sha2-256
> # --- Everything else ---
> ```

> [!WARNING]
> **Not yet validated on PVE clusters.**
> The ssh-audit recommendation *6. Implement connection rate throttling* has not yet been tested. Test carefully in a lab before rollout.
> If you choose to implement it, use the same firewall backend configured in PVE
> Do not mix iptables and nftables rules on the same node; only one backend is active at a time.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.1.5 Enable Full-Disk Encryption

**Level 3**

**Description**\
Protects data at rest, guarding against physical theft or drive RMA.
LUKS2 is used for block-device encryption; keys are required at boot.

**Measures**

1. Install Debian 12 with LUKS-encrypted LVM **before** adding the Proxmox repository.
2. Store recovery keys in an offline password manager or HSM.
3. **If you deploy ZFS:** consider **ZFS native encryption** at the dataset/zvol level instead of whole-disk LUKS, to allow per-dataset keys and more flexible unlock workflows.
 Choose based on your operational model and recovery plan.

> [!WARNING]
> Controls have **not** yet been validated. Test thoroughly.

> [!NOTE]
> Performance impact is typically < 5 % on modern CPUs with AES-NI.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.1.6 Dedicated Filesystem for /var/lib/vz

**Level 1**

**Description**\
Isolates Proxmox VE local directory storage (`/var/lib/vz`) from the root filesystem to prevent space exhaustion from guest images, ISOs, and templates.
Enables safe mount options (`defaults,discard,nodev,nosuid`) without breaking tooling. **Do not** use `noexec` here, guest hooks and maintenance tools may need to run from this path.

**Measures**

- **New install (LVM + XFS example)**
  ```bash
  lvcreate -L <<SIZE>> -n vz <<VG>>
  mkfs.xfs /dev/<<VG>>/vz
  mkdir -p /var/lib/vz
  ```
  Add to `/etc/fstab`:
  ```fstab
  /dev/<<VG>>/vz  /var/lib/vz  xfs  defaults,discard,nodev,nosuid  0 2
  ```
  Then mount and verify:
  ```bash
  systemctl daemon-reload
  mount -a
  mount | grep \/var\/lib\/vz
  ```

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.1.7 Enable Debian “non-free-firmware” repositories

**Level 1**

**Description**\
Enable Debian non-free-firmware alongside main and contrib to ensure required firmware and microcode are available.

**Measures**

- Example `/etc/apt/sources.list`:

  ```ini
  deb http://deb.debian.org/debian bookworm main contrib non-free-firmware
  deb http://deb.debian.org/debian bookworm-updates main contrib non-free-firmware
  deb http://security.debian.org/debian-security bookworm-security main contrib non-free-firmware
  ```

- `apt update` then install required microcode and firmware packages as needed.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.1.8 Install CPU microcode

**Level 1**

**Description**\
Ensures the latest vendor microcode mitigations and stability fixes are applied at boot. Addresses CPU errata and security vulnerabilities that cannot be fully fixed by system firmware alone.

**Measures**

- Install CPU microcode updates:
   - Intel: `apt install intel-microcode`
   - AMD: `apt install amd64-microcode`
   - Reboot to apply (microcode is loaded at boot).

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

#### 1.2 Base PVE

**At this point, PVE is installed.**

---

##### 1.2.1 Secure Boot

###### 1.2.1.1 Enable UEFI Secure Boot

**Level 3**

**Description**\
Prevents malicious or unsigned kernel modules from loading by validating the boot chain against keys stored in UEFI NVRAM.

**Measures**

1. Follow the [PVE wiki guide](https://pve.proxmox.com/wiki/Secure_Boot_Setup)
2. Stage kernel updates on a non-critical node first.

> [!WARNING]
> Controls have **not** yet been validated. Test thoroughly.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

###### 1.2.1.2 Kernel Lockdown (Integrity Mode)

**Level 3**

**Description**\
When Secure Boot is enabled, the parameter `lockdown=integrity` blocks unsigned kernel modules, restricts access
to `/dev/mem`, and kernel-space tampering, even by a compromised root account.

**Measures**

1. Confirm Secure Boot:
   ```bash
   mokutil --sb-state   # should report 'SecureBoot enabled'
   ```
2. Add GRUB parameter:
   ```ini
   GRUB_CMDLINE_LINUX_DEFAULT="quiet lockdown=integrity"
   ```
   ```bash
   update-grub
   reboot
   ```
3. Verify after reboot:
   ```bash
   cat /sys/kernel/security/lockdown
   # Expected: [integrity] confidentiality none
   ```

> [!WARNING]
> Controls have **not** yet been validated. Test thoroughly.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.2.2 Network Separation

**Level 1**

**Description**\
Separates IPMI, management, cluster, storage, and tenant traffic.
This limits lateral movement opportunities for an attacker and reduces broadcast traffic.

**Measures**

- Place the host's IPMI interface in a dedicated **OoB-management VLAN** that is **not** routed to the Internet.
- Place the PVE management interface in a dedicated **management VLAN** that is **not** routed to the Internet.
- Use additional VLANs or NICs for:
   - **Cluster traffic** (Corosync / Ceph) - non-routable - at least **two** interfaces
   - **Storage traffic** (iSCSI / NFS / Ceph) - non-routable
   - **Guest networks** (VM / CT)
- Enforce inter-VLAN firewall rules at the router and/or PVE-Firewall layer.
- Do **not** assign a host IP address to guest/tenant bridges.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.2.3 Maintain a Valid Proxmox Subscription

**Level 1**

**Description**\
Guarantees access to the **Enterprise update repository**, long-term maintenance fixes, and official vendor support.
This is an **operational** control for maintainability and compliance evidence in regulated environments. It is **not** a security hardening control on its own.

**Measures**

1. Purchase a PVE subscription that matches the node tier (*Community, Basic, Standard,* or *Premium*).  
2. Upload the key: `<<Node>> ▸ Subscription ▸ Upload Subscription Key`
3. Enable the enterprise repository and disable no-subscription.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.2.4 Enable the PVE Firewall

**Level 1**

**Description**\
The PVE firewall is a cluster-aware abstraction over `iptables`/`nftables`. Enabling it **replaces** the raw host-based firewall controls described in *CIS Debian 12 Benchmark § 4*.
Maintain rules centrally in the GUI or API and inherit them down the object tree (Datacenter → Cluster → Node → VM/CT).

**Measures**

1. `Datacenter ▸ Firewall`
   - **Add** rules to permit 8006/TCP (GUI), 22/TCP (SSH) and any other needed ports from **trusted** subnets only.
2. `Datacenter ▸ Firewall ▸ Options` **Firewall = Yes**.
   - Default policies: **INPUT**: DROP, **OUTPUT**: ACCEPT.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.2.5 PVE Firewall - Default FORWARD Policy “DROP”

**Level 2**

**Description**\
The PVE firewall is a cluster-aware abstraction over `iptables`/`nftables`. When enabled it **replaces** the host-based firewall controls in *CIS Debian 12 Benchmark § 4*.
Rules can be maintained centrally (GUI or API) and inherited down the object tree (Datacenter → Cluster → Node → VM/CT).
Setting the default **FORWARD** policy to **DROP** blocks all inter-guest or routed traffic unless you explicitly allow it, hardening the cluster against lateral movement.

**Measures**

1. Complete **1.2.4 Enable the PVE Firewall**.
2. Navigate to **Datacenter ▸ Firewall ▸ Options** and set:
   - **FORWARD** = **DROP**
3. For every Node:
   - **Node ▸ Firewall ▸ Options ▸ nftables = Yes**
4. For every VM/CT:
   1. Enable the firewall on the NIC: `VM/CT ▸ Hardware ▸ <<Network Device>> ▸ Firewall = Yes`.
   2. Enable the firewall at guest scope: `VM/CT ▸ Firewall ▸ Options ▸ Firewall = Yes`.
   3. Add the allow-rules (security groups or IP sets) that reflect the VM/CT’s legitimate communication paths.

> [!CAUTION]
> This step requires the **nftables** backend. The nftables firewall is currently in tech preview.
> **Validate on a lab node first.**
> Forward rules are ignored when the legacy iptables backend is active.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.2.6 Review/Configure Kernel Samepage Merging (KSM)

**Level 2**

**Description**\
Kernel Samepage Merging (KSM) deduplicates identical memory pages across VMs/CTs.
While this can reduce RAM usage, it also enables cross‑VM side‑channel attacks based on deduplication timing.
In multi‑tenant or mixed‑trust clusters, **disable KSM**. In single‑tenant clusters where you fully trust all guests, you may enable KSM **after a risk review**.

**Measures**

- **Check current state**
  ```bash
  systemctl status ksmtuned
  cat /sys/kernel/mm/ksm/run    # 0=stopped, 1=running, 2=stop & unmerge
  ```

- **Disable KSM** *(recommended for multi‑tenant / security‑sensitive)*:
  ```bash
  systemctl disable --now ksmtuned 2>/dev/null
  systemctl disable --now ksm 2>/dev/null
  echo 2 > /sys/kernel/mm/ksm/run     # stop and unmerge existing pages
  ```

- **Verify status/metrics**
  ```bash
  grep -E 'full_scans|pages_merged|pages_sharing|run' /sys/kernel/mm/ksm/*
  ```

- **Leave KSM stopped**
   ```bash
   echo 0 > /sys/kernel/mm/ksm/run
   ```

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.2.7 Avoid LXC - Run Container Platforms Inside VMs

**Level 1**

**Description**\
Do **not** use LXC containers on the Proxmox host. Instead, run container platforms (e.g., Docker, Kubernetes) inside a fully virtualized VM.
This ensures proper isolation and keeps the hypervisor dedicated to virtualization only.

**Measures**

- Provision a dedicated VM for your container runtime.
- Apply the guest OS and container runtime hardening baseline inside that VM.
- Expose only the necessary ports from the *VM* to *FRONTEND* networks.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.2.8 Unprivileged Containers by Default

**Level 1**

**Description**\
Prefer control **1.2.7 Avoid LXC - Run Container Platforms Inside VMs**. If that is not an option in your environment, run LXC containers unprivileged so that the container's root user is mapped to an unprivileged host UID/GID via user namespaces.
This reduces the impact of container escapes and enables safer device and mount handling. Use privileged containers only when a specific, justified need exists.

**Measures**

- **Default for new containers**
   - **GUI**: `Create CT → General` tick **Unprivileged container**.
   - **CLI**: `pct create <<CTID>> <<TEMPLATE>> --unprivileged 1 ...`
- **Storage and mounts**
   - Prefer bind mounts of directories owned by the CT's mapped IDs.
   - Avoid device passthrough to unprivileged CTs unless strictly required.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

#### 1.3 SDN Hardening

**Apply this section only if you enable PVE’s Software‑Defined Networking (SDN) features (Zones/VNets/EVPN). If you do not use SDN, you can skip 1.3 entirely.**

> [!WARNING]
> Controls in section *1.3* have **not** yet been validated. Test thoroughly.

---

##### 1.3.1 SDN Baseline (Zones, VNets, Isolation)

**Level 1**

**Description**\
Establishes clear separation between management, storage and tenant networks when using SDN. VNets live inside Zones and must not overlap with host management.
Avoid bridging host management into tenant VNets.

**Measures**

- `Datacenter ▸ SDN`:
   - Create one or more **Zones** (e.g., *simple*, *vxlan*, or *evpn*) to group VNets.
   - For each tenant or environment, create a dedicated **VNet** in the appropriate Zone. Assign unique subnets and tags/VNIs.
   - **Enable Firewall** on each VNet.
- Keep the **host management interface** on a separate bridge; **do not** attach a host IP to tenant/guest VNets.
- Document address plans to ensure **no overlapping CIDRs** across VNets.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.3.2 SDN Firewall Defaults (VNet‑level)

**Level 1**

**Description**\
Applies default‑deny at the VNet edge to reduce lateral movement between guests and VNets. **Forwarding rules require the nftables backend.**

**Measures**

1. On every node that participates in SDN, enable nftables backend:  
   `Node ▸ Firewall ▸ Options ▸ nftables = Yes`.
2. For each **VNet**:
   - **Enable Firewall**.
   - Set **Default Policy**: **INPUT = DROP**, **OUTPUT = ACCEPT**, **FORWARD = DROP**.
   - Allow only required services (e.g., DNS, DHCP to the approved gateway, application ports).
3. Prefer **security groups** and **IP sets** for reusable allowlists.

> [!CAUTION]
> With the legacy iptables backend, VNet **FORWARD** rules are ignored. Use nftables for VNet‑level forwarding control.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.3.3 DHCP/RA Guard on VNets

**Level 1**

**Description**\
Prevents rogue DHCP servers and malicious IPv6 Router Advertisements inside tenant VNets.

**Measures**

- On each **VNet** firewall:
   - **IPv4**: Allow `UDP 67->68` **only** from the trusted DHCP server or gateway IP/MAC. Drop all other DHCP server traffic.
   - **IPv6**: Allow ICMPv6 **Router Advertisement** only from the designated router. Drop unsolicited RAs from guests.
   - Permit DNS to approved resolvers only (TCP/UDP 53) if you control DNS.
- Validate with `tcpdump` during a maintenance window to ensure only the intended sources pass.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.3.4 SDN Overlay Transport Hardening (VXLAN)

**Level 2**

**Description**\
Limits exposure of the SDN overlay transport. VXLAN uses UDP 4789 between nodes; restrict it to the SDN transport network only.

**Measures**

- Place VXLAN endpoints on a **dedicated transport VLAN/VRF** that is not Internet‑routed.
- On upstream firewalls/ACLs, **allow UDP 4789 only between cluster nodes**; block from untrusted networks.
- Set consistent **MTU** across transport and VNet bridges to avoid fragmentation.
- Monitor overlay health; alert on encapsulation errors or MTU drops.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.3.5 EVPN/BGP Controller Hardening

**Level 2**

**Description**\
Secures EVPN control plane peering when using the integrated BGP/EVPN controller.

**Measures**

- Restrict BGP neighbors to **management/transport** subnets only; block from guest VNets.
- Configure BGP **neighbor authentication** (e.g., TCP MD5/TCP‑AO where supported). Store secrets in a root‑only file.
- Apply **prefix‑lists/route‑maps** to limit advertised and accepted routes.
- Prefer **GTSM/TTL security** where possible; avoid unnecessary `ebgp-multihop`.
- Centralize FRR logs and monitor BGP session flaps.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.3.6 Bridge & Kernel Settings for SDN

**Level 1**

**Description**\
Ensures the Linux bridge path is filtered by the firewall and the host does not act as a router for tenant traffic.

**Measures**

- **Load bridge netfilter** at boot:
   - `/etc/modules-load.d/pve-bridge.conf`

   ```ini
   br_netfilter
   ```

   - Activate now: `modprobe br_netfilter`
- **Persist sysctls** in `/etc/sysctl.d/20-pve-sdn.conf`:

   ```ini
   net.bridge.bridge-nf-call-iptables = 1
   net.bridge.bridge-nf-call-ip6tables = 1
   net.bridge.bridge-nf-filter-vlan-tagged = 1
   net.ipv4.ip_forward = 0
   net.ipv6.conf.all.forwarding = 0
   net.ipv6.conf.default.forwarding = 0
   net.ipv4.conf.all.proxy_arp = 0
   net.ipv4.conf.default.proxy_arp = 0
   ```

   - Apply: `sysctl --system`
- Validate: traffic between VMs in different VNets **does not** pass without explicit allow‑rules.

> [!NOTE]
> Enabling bridge netfilter can increase latency and CPU usage, especially at very high packet rates. Validate performance on your hardware and adjust offloading features only if required.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

### 2 GUI Access & ACLs

#### 2.1 Users

##### 2.1.1 Use Personalized Accounts

**Level 1**

**Description**\
Improves auditing and accountability by assigning each administrator a unique `@pam` (or LDAP) account.

**Measures**

```bash
pveum useradd <<alice@pam>> --comment "<<Alice - PVE Admin>>"
pveum acl modify / --user <<alice@pam>> --role <<PVEAdmin>>
```

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 2.1.2 Grant Least Privilege

**Level 1**

**Description**\
Limits potential blast radius by assigning the **smallest** role necessary (e.g., `PVEAuditor` instead of `PVEAdmin`).

**Measures**

- Map each operational task to the minimal role needed.
- Review assignments quarterly.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 2.1.3 Enable 2FA

**Level 1**

**Description**\
Two-factor authentication (2FA) adds an additional factor (TOTP or YubiKey OTP) to mitigate password compromise.

**Measures**

- `Datacenter ▸ Permissions ▸ Users ▸ Edit ▸ Two-Factor` → enable and enroll token.
- Require 2FA for all `@pam` and `@pve` realms via **Datacenter Options**.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 2.1.4 Break-glass (Emergency) Access

**Level 1**

**Description**\
Maintain a sealed, offline “break-glass” root credential for emergencies **without** 2FA. Use personalized accounts with 2FA for daily operations.

**Measures**

- Configure personalized @pam or directory accounts with 2FA for admins.
- Generate a strong root password and store it offline in a tamper-evident container.
- Log any use of break-glass. Rotate the password immediately after use.

- Password policy:
   - min length: 20
   - min uppercase: 3
   - min lowercase: 3
   - min numbers: 3
   - min special: 3

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

#### 2.2 API Tokens

##### 2.2.1 Use Scoped API Tokens

**Level 1**

**Description**\
For automations, this step replaces password-based authentication with revocable API tokens that can be scoped to specific paths.

**Measures**

- `pveum user token add <<alice@pam myapp --expire 2025-12-31>>`
- Assign ACL on `<</vms/100>>` if the app only manages one VM.
- Review assignments quarterly.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 2.2.2 Grant Least Privilege to Tokens

**Level 1**

**Description**\
Minimizes damage if a token leaks.

**Measures**

- Use roles such as `PVEVMAdmin` rather than `PVEAdmin`.
- Review assignments quarterly.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 2.2.3 Store Tokens Securely

**Level 1**

**Description**\
Prevents plaintext exposure of secrets in scripts or CI logs.

**Measures**

- Store secrets in HashiCorp Vault, CyberArk, Bitwarden, **or a similar** vault solution.  
- Never commit tokens to Git or other version-control systems.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 2.2.4 Rotate Tokens Regularly

**Level 1**

**Description**\
Limits lifetime of compromised tokens.

**Measures**

- Set `--expire` when creating tokens.
- Rotate every 365 days.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

#### 2.3 GUI

##### 2.3.1 Install Trusted Certificates

**Level 1**

**Description**\
Eliminates man-in-the-middle (MITM) risk and browser warnings by replacing each node’s default self-signed certificate
with a certificate issued by an internal CA or Let’s Encrypt.

**Measures**

1. **Per host**: Navigate to `Datacenter ▸ <<node>> ▸ System ▸ Certificates` and upload the full-chain PEM certificate with its private key.  
2. Prefer ACME/Let’s Encrypt for automated issuance, see [2.3.2 Automate Certificate Renewal](#232-automate-certificate-renewal).

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 2.3.2 Automate Certificate Renewal

**Level 1**

**Description**\
Prevents expired-cert outages.

**Measures**

1. **Register a cluster-wide ACME account** at `Datacenter ▸ ACME ▸ Add Account`.
2. **If you are using the DNS-01 challenge, configure the required plugin** under `Datacenter ▸ ACME`.
3. **Per host** (certificates are issued and stored node-locally):  
   1. Add the node’s FQDN at `Node ▸ System ▸ Certificates ▸ ACME`.  
   2. Click **Order Certificate** in the GUI to request and install the certificate.

> [!NOTE]
> ACME accounts and challenge plugins are **cluster-wide** (Datacenter scope), but certificates are issued and stored **per node**.

> [!TIP]
> See the PVE wiki: [Certificate Management](https://pve.proxmox.com/wiki/Certificate_Management)

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 2.3.3 Protect the GUI with Fail2Ban

**Level 1**

**Description**\
Blocks brute-force attempts.

**Measures**

- Add to `/etc/fail2ban/jail.local` (or another **appropriate** *.local* file):

   ```ini
   [sshd]
   backend=systemd
   enabled = true
   port = ssh
   filter = sshd
   logpath = /var/log/auth.log
   maxretry = 3
   findtime = 2h
   bantime = 1h
   [proxmox]
   enabled = true
   port = https,http,8006
   filter = proxmox
   backend = systemd
   maxretry = 3
   findtime = 2h
   bantime = 1h
   ```

- Create `/etc/fail2ban/filter.d/proxmox.conf` (or another appropriate file):

   ```ini
   [Definition]
   failregex = pvedaemon\[.*authentication failure; rhost=<HOST> user=.* msg=.*
   ignoreregex =
   ```

- Restart fail2ban `systemctl restart fail2ban`
- Check fail2ban status:
   - `fail2ban-client status`
   - `fail2ban-client status sshd`
   - `fail2ban-client status proxmox`

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

### 3 Cluster Protections

##### 3.1 Provide Redundant Corosync Links

**Level 1**

**Description**\
Maintains quorum and keeps the cluster operational even if a NIC, switch, or VLAN fails by routing Corosync traffic over at least **two independent network interfaces** (`ring0` and `ring1`).

**Measures**

1. Equip every node with a second NIC on a separate switch or VLAN dedicated to Corosync.
2. Define both rings in `/etc/pve/corosync.conf`, e.g.:

   ```ini
   nodelist {
     node {
       name node1
       ring0_addr  <<10.10.0.1>>
       ring1_addr  <<10.20.0.1>>
     }
   }
   ```

3. Reload configuration: `systemctl restart corosync` (one node at a time).
4. Validate redundancy:
   - `corosync-cfgtool -s` -> both rings show link status: **OK**.
   - Temporarily unplug one ring; `pvecm status` must still report **Quorate**.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 3.2 Secure Inter-Node Communication

**Level 1**

**Description**\
Enables SSL/TLS and HMAC validation for Corosync traffic (`secauth: on`), protecting cluster messaging from spoofing.

**Measures**

Verify `secauth` is enabled (default true); no change needed unless explicitly disabled.

- `/etc/pve/corosync.conf`

   ```ini
   totem {
     secauth: on
   }
   ```

- If changed, restart one node at a time.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 3.3 Ceph Pool Sizing and Failure Domains

**Level 1**

**Description**\
Set `size` and `min_size` to meet failure tolerance and configure CRUSH rules so replicas land on different failure domains.

**Measures**

- Typical replication
   - `size = 3`, `min_size = 2` for tolerance of one OSD or host failure.
- CRUSH rules
   - Choose failure domain per risk: host, chassis, rack or row.
   - Verify placement: `ceph osd tree` and `ceph osd crush rule list` then test with ceph osd map.
- Health checks
   - Alert on `HEALTH_WARN` and `HEALTH_ERR`.
   - Simulate failures in a lab to confirm data remains available with your min_size.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 3.4 Ceph OSD Encryption

**Level 2**

**Description**\
Encrypts OSD data.

**Measures**

- Tick **Encryption** when creating each OSD.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 3.5 Ceph Messenger Encryption (In-Flight)

**Level 2**

**Description**\
Encrypts client<->OSD and OSD<->OSD traffic using Ceph Messenger “secure” mode, preventing eavesdropping or tampering on the network.

**Measures**

1. Edit `/etc/ceph/ceph.conf` on every node:

   ```ini
   [global]
   ms_bind_msgr2 = true         # bind messenger v2 (required for 'secure' modes)
   ms_encrypt = true            # enable wire-encryption
   ms_cluster_mode = secure     # require encryption on cluster network
   ms_service_mode = secure     # all daemon service endpoints
   ms_client_mode = secure      # require encryption on client network
   ms_mon_client_mode = secure  # require encryption for MON client connections
   ms_mon_cluster_mode = secure # require encryption within MON cluster
   ms_mon_service_mode = secure # require encryption for MON service endpoints
   ```

2. Restart daemons:
   `systemctl restart ceph.target`

> [!WARNING]
> Controls have **not** yet been validated. Test thoroughly.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

### 4 Backup & Disaster Recovery

##### 4.1 Enforce 3-2-1 Backup Strategy

**Level 1**

**Description**\
Guarantees data resilience by keeping **three** copies of every critical backup stored on **two** different media or storage tiers,
with at least **one** copy stored off-site or offline.
This mitigates single-point failures, ransomware, and site-wide disasters.

**Measures**

1. Maintain three copies:
   - 1 × production data
   - 2 × independent backups
2. Use two distinct storage types (e.g., local ZFS + Proxmox Backup Server, NFS share + LTO tape, or Ceph RBD + S3 object storage).
3. Keep one copy off-site or offline (remote datacenter, immutable object-store bucket with versioning, or vaulted storage).

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 4.2 Backup Host Configuration

##### 4.2.1 Backup Host Configuration

**Level 1**

**Description**\
Backs up the entire Proxmox VE host configuration, cluster files, networking, storage maps and custom scripts to a Proxmox Backup Server (PBS), so you can rebuild a node from bare metal without relying on VM/CT snapshots.

**Measures**

1. **Verify the client is present** (it ships with PVE 8, but older hosts may lack it):

   ```bash
   apt update && apt install proxmox-backup-client -y
   ```

2. Store credentials in a root read-only file:

   ```bash
   # Create an API token with Datastore.Backup privilege only
   # Token name: hostbackup@pbs
   echo 'PBS_REPOSITORY="<<hostbackup@pbs@backup.example.com:datastore>>"
   PBS_PASSWORD=<<API_TOKEN>>
   PBS_FINGERPRINT=<<PBS_FINGERPRINT>>' > /root/.pbs-cred
   chmod 600 /root/.pbs-cred
   ```

3. Automate with systemd **daily**
   - `/etc/systemd/system/pbc-host-backup.service`:

      ```ini
      [Unit]
      Description=Host-config backup to PBS
      Wants=network-online.target
      After=network-online.target
      [Service]
      Type=oneshot
      EnvironmentFile=/root/.pbs-cred
      ExecStart=/usr/bin/proxmox-backup-client backup \
                root.pxar:/ \
                etc.pxar:/etc \
                --include-dev /boot \
      Nice=10
      IOSchedulingClass=best-effort
      IOSchedulingPriority=7
      ```

   - `/etc/systemd/system/pbc-host-backup.timer`:

      ```ini
      [Unit]
      Description=Daily host-config backups
      [Timer]
      # Run every day at 06:00 local
      OnCalendar=*-*-* 06:00:00
      Persistent=true
      RandomizedDelaySec=300
      [Install]
      WantedBy=timers.target
      ```

   - `systemctl daemon-reload && systemctl enable --now pbc-host-backup.timer`

4. Verify restores **quarterly**: `proxmox-backup-client restore pveconf.pxar /tmp/pve-restore --verify`

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 4.2.2 Encrypt Host Configuration Backups

**Level 2**

**Description**\
Encrypts the host-configuration archives **before** they leave the PVE Node.
Even if the transport or remote PBS is compromised, backup contents remain confidential.
**Warning:** losing the encryption key makes the backups **unrecoverable**.

**Measures**

1. Create a client encryption key (root-only):

   ```bash
   proxmox-backup-client key create /root/.pbs-enc-key.json --kdf scrypt
   chmod 600 /root/.pbs-enc-key.json
   ```

   - When prompted, enter a strong passphrase for the key.
   - Store an **offline** copy of the key (Vault/HSM or encrypted offline media).

2. Add key to the `.pbs-cred` file:

   ```bash
   echo 'PBS_ENCRYPTION_KEY_FILE=/root/.pbs-enc-key.json
   PBS_ENCRYPTION_PASSWORD=<<ENC-KEY-PASSWORD>>' >> /root/.pbs-cred
   chmod 600 /root/.pbs-cred
   ```

3. Enable encryption in the systemd job:
   - Append the following arguments to the existing `ExecStart=` line in `/etc/systemd/system/pbc-host-backup.service`:

      ```ini
      # config of 4.2.1
          --crypt-mode encrypt \
          --keyfile ${PBS_ENCRYPTION_KEY_FILE}
      ```

   - Example:

      ```ini
      [Unit]
      Description=Host-config backup to PBS
      Wants=network-online.target
      After=network-online.target
      [Service]
      Type=oneshot
      EnvironmentFile=/root/.pbs-cred
      ExecStart=/usr/bin/proxmox-backup-client backup \
                root.pxar:/ \
                etc.pxar:/etc \
                --include-dev /boot \
                --crypt-mode encrypt \
                --keyfile ${PBS_ENCRYPTION_KEY_FILE}
      Nice=10
      IOSchedulingClass=best-effort
      IOSchedulingPriority=7
      ```

   - Then reload units:

      ```bash
      systemctl daemon-reload
      systemctl restart pbc-host-backup.timer
      ```

4. Verify encryption on the server:
   - In the PBS UI or via CLI, confirm the backup shows as encrypted.

> [!NOTE]
> Key management is critical: escrow a copy, document recovery, and restrict file permissions (600, root-owned).
> Rotate keys on a planned schedule; re-encrypt old backups only if policy requires.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 4.3 Automate Backups

**Level 1**

**Description**\
Ensures fresh backups exist without relying on human action.

**Measures**

- Create a **daily** schedule to backup VMs/CTs to PBS.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 4.4 Encrypt Backups

**Level 2**

**Description**\
Protects backups stored off-site or in object storage from unauthorized access.

**Measures**

- Use PBS client-side encryption (`Datacenter ▸ Storage` PBS options **Encryption**).
- Store an **offline** copy of the key (Vault/HSM or encrypted offline media).

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 4.5 Notify on Failed Backup

**Level 1**

**Description**\
Triggers an immediate alert whenever a backup job fails to ensure missing restore points are noticed before the next verification cycle.

**Measures**

- `Datacenter ▸ Backup` for every Backup set **Send email** to **On failure only** (or **Always** if you prefer positive confirmation).

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 4.6 Document and Test Restores

**Level 1**

**Description**\
Validates that backups are usable in an outage.

**Measures**

- Quarterly restore drill to isolated test VLAN.
- Record Recovery Time Objective (RTO) and Recovery Point Objective (RPO).

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

### 5 Logging, Monitoring, Auditing & Documentation

#### 5.1 Logging

##### 5.1.1 Centralized Logging

**Level 1**

**Description**\
Provides tamper-evident storage and allows for correlation of security events.

**Measures**

In **addition** to *CIS Debian 12 Benchmark § 6.1*, forward:

- `/var/log/pve*`

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 5.1.2 Auditd for /etc/pve

**Level 2**

**Description**\
Tracks configuration changes in the distributed PVE filesystem.

**Measures**

- Create a **persistent** audit rule file:

  `/etc/audit/rules.d/90-pve.rules`
  ```ini
  -w /etc/pve -p wa -k pve-config
  ```

- Load rules and verify:
   - `augenrules --load`, rebuild /etc/audit/audit.rules from rules.d
   - `systemctl restart auditd`, **alternative** reload if augenrules isn’t present
   - `auditctl -l | grep pve-config`, should list the /etc/pve watch
   - `ausearch -k pve-config`, view matching audit events

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

#### 5.2 Monitoring

##### 5.2.1 Centralized Metrics

**Level 1**

**Description**\
Detects capacity issues before they become outages.

**Measures**

- Export to Prometheus with `pve_exporter`.
- Dashboards in Grafana.

> [!NOTE]
> Or another **appropriate** monitoring solution.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 5.2.2 Alerting

**Level 1**

**Description**\
Turns raw metrics into actionable alerts.

**Measures**

Create alerts **at least** for:

- CPU > 80 %
- Disk > 80 %
- RAM > 80 %
- Ceph health **is not** `HEALTH_OK`

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

#### 5.3 Auditing

##### 5.3.1 System Audits

**Level 2**

**Description**\
Objective measurement of compliance drift over time.

**Measures**

- Run OpenSCAP or other quarterly **and** after major upgrades.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 5.3.2 Rootkit Detection

**Level 2**

**Description**\
Detects known rootkits in userland and kernel space.

**Measures**

- `apt install rkhunter` and add to `cron.daily`.

> [!WARNING]
> Controls have **not** yet been validated. Test thoroughly.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

#### 5.4 Documentation

**Level 1**

**Description**\
Maintains institutional knowledge and supports audits.

**Measures**

- Update network diagrams, inventory, and change logs after ***every** significant change.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

## Exception Handling

Document deviations from this guide with justifications, risk acceptance, and approval signatures.

---

## Appendices

### A. CIS Benchmark

All CIS control references - section numbers (e.g., **1.1.1**), Level tags (**Level 1** / **Level 2**), and remediations map **exclusively** to the **CIS Debian Linux 12 Benchmark v1.1.0 (2024-09-26)**.

### B. Example Ansible Snippets

```yaml
---
- name: Harden PVE
  hosts: pve
  become: true
  become_method: ansible.builtin.su
  tasks:
```

- CIS Level 1 *ansible-lockdown* role

`ansible-galaxy role install ansible-lockdown.deb12_cis`

```yaml
- name: Run ansible-lockdown Deb 12 CIS (Level 1)
  ansible.builtin.include_role:
    name: "ansible-lockdown.deb12_cis"
    apply:
      tags:
        - level1-server
  vars:
    deb12cis_disruption_high: true
    deb12cis_section4: false
    deb12cis_level_2: false
    deb12cis_rule_5_1_20: false
    deb12cis_time_sync_tool: chrony
    deb12cis_remote_log_host: <<log.example.com>>
```

- CIS Level 2 *ansible-lockdown* role

`ansible-galaxy role install ansible-lockdown.deb12_cis`

```yaml
- name: Run ansible-lockdown Deb 12 CIS (Level 2)
  ansible.builtin.include_role:
    name: "ansible-lockdown.deb12_cis"
    apply:
      tags:
        - level2-server
  vars:
    deb12cis_disruption_high: true
    deb12cis_section4: false
    deb12cis_rule_5_1_20: false
    deb12cis_time_sync_tool: chrony
    deb12cis_remote_log_host: <<log.example.com>>
```

### C. Recovery-Drill Checklist

1. Start-of-year cold test: Restore the most recent nightly backup to an isolated lab and boot VMs.
2. Quarterly file-level restore test: Restore on a single VM disk.
3. Ceph OSD failure simulation: Mark one OSD out and verify HEALTH_OK returns post-recovery.
4. Corosync link loss: Disable primary ring interface; ensure quorum re-establishes on ring 1.
5. Document outcomes, time-to-recover, and update runbooks.

### D. Installation checklists (Host and Guest)

#### D.1 Host Install Checklist

- [ ] Firmware, IPMI and BIOS updated
- [ ] Prepare Network segmentation
- [ ] Install Debian with correct partitioning
- [ ] Execute Hardening Guide
- [ ] Create/Update documentation

#### D.2 Guest Install Checklist

- [ ] VM type and machine model selected appropriately
- [ ] VirtIO devices (net, disk), qemu-guest-agent installed
- [ ] Baseline OS hardening profile applied
- [ ] Minimal open services; firewall active inside guest

---

## Change Notes

| Version | Date       | Author              | Key Changes                                    | Reviewed By |
|---------|------------|---------------------|------------------------------------------------|-------------|
| 0.9.0   | 2025-08-31 | HomeSecExplorer     | Initial creation.                              |   --------  |
| 0.9.1   | 2025-09-25 | HomeSecExplorer     | Expanded guide: move Change Notes, 1.2.7 to 1.2.8, 3.3 to 3.4, 3.4 to 3.5; edit 1.1.5 (add ZFS), 1.2.2 (IPMI), rephrase 1.2.3, 1.2.8, 4.2.2/4.4; added 1.1.7 non-free-firmware, 1.1.8 CPU microcode, 2.1.4 break-glass access with password policy, 3.3 Ceph pool sizing and failure domains, Appendix D Installation checklists Host&VMs; minor edits. |   --------  |
| 0.9.2   | 2025-10-05 | HomeSecExplorer     | Remove 1.1.6 noatime mount option |   --------  |
