# Proxmox Backup Server 4.x Hardening Guide

### Version 0.9.1 - January 12, 2026

### Author: [HomeSecExplorer](https://github.com/HomeSecExplorer)

![HomeSecExplorer_Banner](https://github.com/HomeSecExplorer/HomeSecExplorer/blob/main/assets/banner.png?raw=true)

---

## Terms of Use

This guide is provided **“as is,” without warranty of any kind**, whether express or implied.
The author(s) and the [HomeSecExplorer Proxmox Hardening Guide](https://github.com/HomeSecExplorer/Proxmox-Hardening-Guide) project make
**no guarantees** regarding completeness, accuracy, or fitness for any particular purpose. By using this guide, you agree that:

1. **Responsibility**\
   You remain solely responsible for evaluating, testing, and validating every recommendation in your environment.
   Any security control that introduces operational risk **must** be reviewed, adjusted, or rejected by you.
2. **No Liability**\
   The author(s) and contributors are **not liable** for direct, indirect, incidental, or consequential damages arising from the use of this guide, even if advised of the possibility of such damages.
3. **Attribution & Licensing**\
   This guide is released under the **CC BY 4.0 License** (see [../LICENSE](../LICENSE)). You may copy, modify, and distribute the content provided you retain
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

1. [Terms of Use](#terms-of-use)
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
   - [Design principles](#design-principles)
3. [Recommendations](#recommendations)
   - [1 Initial Setup](#1-initial-setup)
      - [1.1 Base OS](#11-base-os)
         - [1.1.1 Apply Debian 13 CIS Level 1](#111-apply-debian-13-cis-level-1)
         - [1.1.2 Apply Debian 13 CIS Level 2](#112-apply-debian-13-cis-level-2)
         - [1.1.3 Configure Automatic Security Updates](#113-configure-automatic-security-updates)
         - [1.1.4 Apply ssh-audit Hardening Profile](#114-apply-ssh-audit-hardening-profile)
         - [1.1.5 Enable Full-Disk Encryption](#115-enable-full-disk-encryption)
         - [1.1.6 Enable Debian “non-free-firmware” repositories](#116-enable-debian-non-free-firmware-repositories)
         - [1.1.7 Install CPU microcode](#117-install-cpu-microcode)
      - [1.2 Base PBS](#12-base-pbs)
         - [1.2.1 Secure Boot](#121-secure-boot)
            - [1.2.1.1 Enable UEFI Secure Boot](#1211-enable-uefi-secure-boot)
            - [1.2.1.2 Kernel Lockdown (Integrity Mode)](#1212-kernel-lockdown-integrity-mode)
         - [1.2.2 Network Separation](#122-network-separation)
         - [1.2.3 Maintain a Valid Proxmox Subscription](#123-maintain-a-valid-proxmox-subscription)
         - [1.2.4 Dedicated Filesystems for Datastores](#124-dedicated-filesystems-for-datastores)
         - [1.2.5 Network-backed Datastores (NFS/SMB)](#125-network-backed-datastores-nfssmb)
         - [1.2.6 Firewall the API/GUI](#126-firewall-the-apigui)
   - [2 Users, API and GUI](#2-users-api-and-gui)
      - [2.1 Users](#21-users)
         - [2.1.1 Use Personalized Accounts](#211-use-personalized-accounts)
         - [2.1.2 Grant Least Privilege](#212-grant-least-privilege)
         - [2.1.3 Enable 2FA](#213-enable-2fa)
         - [2.1.4 Break-glass (Emergency) Access](#214-break-glass-emergency-access)
         - [2.1.5 Privileged Access Model](#215-privileged-access-model-root-sudo-and-shell-access)
      - [2.2 API Tokens](#22-api-tokens)
         - [2.2.1 Use Scoped API Tokens](#221-use-scoped-api-tokens)
         - [2.2.2 Grant Least Privilege to Tokens](#222-grant-least-privilege-to-tokens)
         - [2.2.3 Store Tokens Securely](#223-store-tokens-securely)
         - [2.2.4 Rotate Tokens Regularly](#224-rotate-tokens-regularly)
      - [2.3 GUI](#23-gui)
         - [2.3.1 Install Trusted Certificates](#231-install-trusted-certificates)
         - [2.3.2 Automate Certificate Renewal](#232-automate-certificate-renewal)
         - [2.3.3 Protect the GUI with Fail2Ban](#233-protect-the-gui-with-fail2ban)
   - [3 Datastore Protections](#3-datastore-protections)
      - [3.1 Turn On “verify-new”](#31-turn-on-verify-new)
      - [3.2 Schedule Weekly Verify Job](#32-schedule-weekly-verify-job)
      - [3.3 Set Prune Policy](#33-set-prune-policy)
      - [3.4 Schedule Garbage Collection](#34-schedule-garbage-collection)
      - [3.5 Alert on Verify, Sync, Prune & GC Errors](#35-alert-on-verify-sync-prune--gc-errors)
      - [3.6 Configure Re-Verify After](#36-configure-re-verify-after)
      - [3.7 Remote Sync Jobs](#37-remote-sync-jobs)
   - [4 Backup & Disaster Recovery](#4-backup--disaster-recovery)
      - [4.1 Enforce 3-2-1 Backup Strategy](#41-enforce-3-2-1-backup-strategy)
      - [4.2 Backup Host Configuration](#42-backup-host-configuration)
         - [4.2.1 Backup Host Configuration](#421-backup-host-configuration)
         - [4.2.2 Encrypt Host Configuration Backups](#422-encrypt-host-configuration-backups)
   - [5 Logging, Monitoring, Auditing & Documentation](#5-logging-monitoring-auditing--documentation)
      - [5.1 Logging](#51-logging)
         - [5.1.1 Centralized Logging](#511-centralized-logging)
         - [5.1.2 Auditd for /etc/proxmox-backup](#512-auditd-for-etcproxmox-backup)
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
   - [D. Installation Checklist](#d-installation-checklists-host)
6. [Change Notes](#change-notes)

---

## Overview

- **Scope:** All Proxmox Backup Server installations.
- **Audience:** System administrators, security engineers, and compliance auditors responsible for Proxmox Backup Server deployments.

### Usage Information

This guide provides **prescriptive hardening guidance** for Proxmox Backup Server 4.
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

This guidance was developed and validated on **Proxmox Backup Server 4** running on **Debian 13 “bookworm”** (x86-64).

#### Assumptions

- Commands are executed as **root** in the default shell.
- When using `sudo` or a different shell, confirm command syntax and environmental differences.

#### Installation Note

To satisfy several CIS Debian Benchmark controls (for example, partition layout), install **Debian 13 first** and then add the Proxmox Backup Server repository **instead of** using the Proxmox ISO installer.

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

- *CIS Debian Linux 13 Benchmark* - [CIS Debian](https://www.cisecurity.org/benchmark/debian_linux)
- *Proxmox Backup Server Administration Guide* - [PBS Admin Guide](https://pbs.proxmox.com/docs/index.html)
- *Debian Security Hardening Manual* - [Debian hardening](https://www.debian.org/doc/manuals/securing-debian-manual/index.en.html)

### Definitions & Abbreviations

| Term    | Definition                   |
| ------- | ---------------------------- |
| **PBS** | Proxmox Backup Server        |
| **CIS** | Center for Internet Security |
| **ACL** | Access Control List          |
| **2FA** | Two-Factor Authentication    |
| **ACME** | Automated Certificate Management Environment; protocol used by Let’s Encrypt |

### System Inventory Template

Maintain a current inventory of all PBS nodes.

Update the table after **every** hardware or configuration change.

| Hostname | IP Address | Role           | OS Version | CIS Level | Hardened On | Location | Notes           |
| -------- | ---------- | -------------- | ---------- | --------- | ----------- | -------- | --------------- |
| pbs01    | 10.0.10.20 | Primary PBS    | Debian 13  | Level 1   | Dec 2025    | DC1-R1   | No subscription |
| pbs02    | 10.0.10.21 | Secondary PBS  | Debian 13  | Level 2   | Dec 2025    | DC2-R1   | No subscription |

### Hardening Level Selection

| Level            | Summary                                                                      | When to Use                                             |
| ---------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------- |
| **1 - Baseline** | Minimal operational impact; mandatory for **all** PBS nodes.                 | Always                                                  |
| **2 - Enhanced** | Additional defense-in-depth controls. Evaluate each control for feasibility. | Regulated or high-security workloads                    |
| **3 - Advanced** | Maximum hardening; may introduce downtime or complexity.                     | Only when data sensitivity or threat model justifies it |

### Design principles

These principles define the intent behind the checklist items below. They guide the most important design decisions and set boundaries for what this guide assumes.

- **PBS is a backup vault, not a general-purpose server.** Avoid using PBS as a NAS, Docker host, app server, or anything else. Extra services add risk to your last line of defense.
- **Strong separation of duties and access paths.** Design so one compromised credential does not equal “delete all backups.” Restrict who can modify datastores, retention, prune policies, and permissions. Limit where PBS is reachable from.
- **Retention and destructive actions are security controls.** Use retention and pruning intentionally and monitor destructive operations. Incidents often target recovery options first.
- **Assume the network is hostile; encrypt and restrict.** Encrypt where appropriate, protect encryption keys, and restrict outbound access from PBS. Backups often contain the most sensitive data in the environment.
- **Offsite or offline backups are required for real resilience.** PBS is excellent for fast restores, but you still need a separate recovery source for worst-case scenarios.
- **Restore testing is part of hardening.** Regularly test file restores, VM restores, and “whole host rebuild” assumptions. A backup that was never tested is not a reliable control.

---

## Recommendations

### 1 Initial Setup

Apply these controls during or immediately after installation. Retrofitting them later can be disruptive.

#### 1.1 Base OS

---

##### 1.1.1 Apply Debian 13 CIS Level 1

**Level 1**

**Description**\
Establishes a secure **minimum** configuration for Debian 13 that balances security with stability. Controls include partitioning,
secure permissions, basic hardening of SSH, and kernel parameter tuning.

**Measures**

- Apply **all** remediations in the *CIS Debian 13 Benchmark Level 1 - Server* profile.

> [!NOTE]
> During the *CIS Debian 13 Benchmark § 4 (Host-Based Firewall) remediation*, remember to **allow** Proxmox Backup Server traffic.
> For more details look at [1.2.6](#126-firewall-the-apigui)

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.1.2 Apply Debian 13 CIS Level 2

**Level 2**

**Description**\
Adds defense-in-depth measures, such as stricter file-permission policies and advanced kernel hardening, suitable for regulated or high-risk environments.
May impact certain workloads or third-party software.

**Measures**

- Apply **all** remediations in the *CIS Debian 13 Benchmark Level 2 - Server* profile after completing Level 1.
- Validate services such as Ceph, ZFS, and PBS in a **lab** before rolling out to production.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

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

> [!TIP]
> For Ansible automation, check out the *HomeSecExplorer* role for autoupdate.
> See [Appendix B](#b-example-ansible-snippets) for examples.
> [autoupdate Role](https://github.com/HomeSecExplorer/ansible-role-autoupdate)

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.1.4 Apply ssh-audit Hardening Profile

**Level 2**

**Description**\
Apply the recommended server and client-side hardening settings from the ssh-audit Debian 13 guides.
These settings remove legacy ciphers, MACs, and key-exchange algorithms that baseline CIS controls still permit.

**Measures**

1. Follow the *ssh-audit* Debian 13 **server** guide.
2. Follow the *ssh-audit* Debian 13 **client** guide.

> [!TIP]
> For Ansible automation, check out the *HomeSecExplorer* role for ssh-audit.
> See [Appendix B](#b-example-ansible-snippets) for examples.
> [sshaudit Role](https://github.com/HomeSecExplorer/ansible-role-sshaudit)

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.1.5 Enable Full-Disk Encryption

**Level 3**

**Description**\
Protects data at rest, guarding against physical theft or drive RMA.
LUKS2 is used for block-device encryption; keys are required at boot.

**Measures**

1. Install Debian 13 with LUKS-encrypted LVM **before** adding the Proxmox repository.
2. Store recovery keys in an offline password manager or HSM.
3. **If you deploy ZFS:** consider **ZFS native encryption** at the dataset/zvol level instead of whole-disk LUKS, to allow per-dataset keys and more flexible unlock workflows.
 Choose based on your operational model and recovery plan.

> [!WARNING]
> Controls have **not** yet been validated. Test thoroughly.

> [!NOTE]
> Performance impact is typically < 5 % on modern CPUs with AES-NI.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.1.6 Enable Debian “non-free-firmware” repositories

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

- Example deb822 format `/etc/apt/sources.list.d/debian.sources`:

   ```ini
   *
   Components: main non-free-firmware contrib
   *
   ```

- `apt update` then install required microcode and firmware packages as needed.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.1.7 Install CPU microcode

**Level 1**

**Description**\
Ensures the latest vendor microcode mitigations and stability fixes are applied at boot. Addresses CPU errata and security vulnerabilities that cannot be fully fixed by system firmware alone.

**Measures**

- Install CPU microcode updates:
   - Intel: `apt install intel-microcode`
   - AMD: `apt install amd64-microcode`
   - Reboot to apply (microcode is loaded at boot).

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

#### 1.2 Base PBS

**At this point, PBS is installed.**

---

##### 1.2.1 Secure Boot

###### 1.2.1.1 Enable UEFI Secure Boot

**Level 3**

**Description**\
Prevents malicious or unsigned kernel modules from loading by validating the boot chain against keys stored in UEFI NVRAM.

**Measures**

1. Follow the [PBS docs](https://pbs.proxmox.com/docs/sysadmin.html#secure-boot)
2. Stage kernel updates on a non-critical node first.

> [!WARNING]
> Controls have **not** yet been validated. Test thoroughly.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

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
> Controls have **not** yet been validated. Test thoroughly.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.2.2 Network Separation

**Level 1**

**Description**\
Separates IPMI, management and backup traffic from backend storage traffic.
This reduces the risk of lateral movement and prevents backup traffic from congesting the storage network.

**Measures**

- Place the host's IPMI interface in a dedicated **OoB-management VLAN** that is **not** routed to the Internet.
- Place the PBS management interface in a dedicated **management VLAN** that is **not** routed to the Internet.
- Mount NFS, SMB, or other backend storage on a dedicated **storage VLAN** that is **not** routed to the Internet.
- Enforce inter-VLAN firewall rules at the router and/or Host Firewall layer.
- Set appropriate MTU sizes.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.2.3 Maintain a Valid Proxmox Subscription

**Level 1**

**Description**\
Guarantees access to the **Enterprise update repository**, long-term maintenance fixes, and official vendor support.
This is an **operational** control for maintainability and compliance evidence in regulated environments. It is **not** a security hardening control on its own.

**Measures**

1. Purchase a PBS subscription that matches the node tier (*Community, Basic, Standard,* or *Premium*).
2. Upload the key: `Configuration --> Subscription --> Upload Subscription Key`
3. Enable the enterprise repository and disable no-subscription.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.2.4 Dedicated Filesystems for Datastores

**Level 1**

**Description**\
Place every PBS datastore on its **own mount point** or **own ZFS dataset**.
This isolates backup writes from the OS, helps avoid full-disk conditions, and allows stricter mount/ZFS options.

**Measures**

- Create a **separate block device/LV/mount** per datastore (recommended), or a separate ZFS dataset per datastore.
- Use the following mount options and properties:
   - ext4 / XFS
      - mount options: `defaults,nodev,nosuid,noexec`
- **ZFS dataset**
   - properties:

      ```bash
      # example pool/dataset: tank/pbs/ds1
      zfs create -o mountpoint=<</mnt/pbs-ds1>> <<tank/pbs/ds1>>
      zfs set compression=zstd-3   <<tank/pbs/ds1>>
      zfs set xattr=sa             <<tank/pbs/ds1>>
      zfs set acltype=posixacl     <<tank/pbs/ds1>>
      zfs set exec=off             <<tank/pbs/ds1>>
      zfs set setuid=off           <<tank/pbs/ds1>>
      ```

> [!WARNING]
> ZFS datasets have **not** yet been validated. Test thoroughly.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.2.5 Network-backed Datastores (NFS/SMB)

**Level 2**

**Description**\
Local filesystems (ext4/XFS/ZFS) are preferred for primary PBS datastores. If you must use **network shares**, limit them to secondary/sync targets or carefully hardened environments.
Configure authentication and transport encryption, and use mount options that reduce attack surface and boot-time risk.

**Measures**

- **General**
   - Place shares on an isolated **storage VLAN** not routed to the Internet.
   - Restrict server exports to the PBS host IPs only and firewall both directions.
   - Mount with `nodev,nosuid,noexec,_netdev` and systemd automount to avoid boot hangs.
   - Monitor: alert if the datastore path is **not mounted** during backup windows.

- **NFS (preferred over SMB when available)**
   - Use **NFSv4.1/4.2** over TCP with Kerberos privacy:
      - Client mount options: `rw,vers=4.2,sec=krb5p,hard,nodev,nosuid,noexec,_netdev,x-systemd.automount,x-systemd.idle-timeout=600`
   - **Server-side export** hardening (on the NFS server):
      - Prefer `sync` exports (with SLOG if using ZFS), `root_squash`, `sec=krb5p`, and limit `rw` to PBS IPs.
      - Disable insecure legacy protocols/versions; use `v4 only` where possible.

> **If Kerberos is not available, you may temporarily use sec=sys only on an isolated storage VLAN with IP allowlists, root_squash, and strict exports.**
> **For confidentiality and integrity, prefer sec=krb5p.**

- **SMB/CIFS (when NFS is not feasible)**
   - Use SMB 3.x with encryption and Kerberos where available:
      - Client mount options (example `/etc/fstab`):

        ```fstab
        //filesrv.example.com/pbs-ds1  /mnt/pbs-ds1  cifs  rw,vers=3.1.1,seal,sec=krb5,credentials=/root/.smbcred-pbs,serverino,cache=none,actimeo=30,nodev,nosuid,noexec,_netdev,x-systemd.automount,x-systemd.idle-timeout=600  0  0
        ```

      - Create `/root/.smbcred-pbs` with `chmod 600`:

        ```ini
        username=<<pbs-service-user>>
        password=<<strong-password-or-token>>
        domain=<<AD.DOMAIN>>   # optional; required for Kerberos setups
        ```

      - If Kerberos is unavailable, use `sec=ntlmssp` with strong passwords and IP allowlists (reduced security).
   - **Server-side share** hardening:
      - Require SMB 3.0+, enable encryption, disable guest/anonymous access, and restrict by host/IP and group.

> [!WARNING]
> SMB/CIFS mounts have **not** yet been validated. Test thoroughly.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 1.2.6 Firewall the API/GUI

**Level 1**

**Description**\
Restrict access to SSH and PBS GUI/API on TCP 8007 to trusted management networks. Do not expose SSH and TCP 8007 directly to the Internet.

**Measures**

1. Identify your trusted networks:
   - **Management subnet(s)**
   - **Backup subnet(s) with PVE nodes**

2. Allow only those subnets to reach TCP **8007** (GUI/API) and TCP **22** (SSH). Set the default **INPUT** policy to **DROP**.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

### 2 Users, API and GUI

#### 2.1 Users

##### 2.1.1 Use Personalized Accounts

**Level 1**

**Description**\
Improves auditing and accountability by assigning each administrator a unique `@pam`, `@pbs` or LDAP account.

**Measures**

```bash
proxmox-backup-manager user create <<alice@pbs>> --comment "<<Alice - Admin>>"
proxmox-backup-manager acl update <</datastore>> <<Admin>> --auth-id <<alice@pbs>>
```

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 2.1.2 Grant Least Privilege

**Level 1**

**Description**\
Limits potential blast radius by assigning the **smallest** role necessary (e.g., `DatastoreAdmin` instead of `Admin`).

**Measures**

- Map each operational task to the minimal role needed.
   - `proxmox-backup-manager acl update <</datastore>> <<DatastoreAdmin>> --auth-id <<alice@pbs>>`
- Review assignments quarterly.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 2.1.3 Enable 2FA

**Level 1**

**Description**\
Two-factor authentication (2FA) adds an additional factor (TOTP or YubiKey OTP) to mitigate password compromise.

**Measures**

- `Configuration --> Access Control --> Two Factor Authentication` --> enable and enroll token.

> [!NOTE]
> **Exception for** `root`, see [2.1.4](#214-break-glass-emergency-access)

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

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

##### 2.1.5 Privileged Access Model (Root, Sudo, and Shell Access)

**Level 1**

**Description**\
Routine administration should be performed through named user accounts with least-privilege access. Keep `root@pam` for emergencies only and ensure actions are attributable to an individual user.
PBS adds an additional layer through PBS RBAC (roles + paths) and API tokens. This section defines what “normal” administration looks like on a hardened system.

**Measures**

- Use the PBS UI/API for day-to-day administration with named accounts and least-privilege RBAC.
- Treat interactive OS shell access as the exception, not the norm.
- Treat `root@pam` as break-glass only (see [2.1.4](#214-break-glass-emergency-access)). Do not use it for daily operations.

- Define access tiers (lower tier number = higher privilege and higher risk):
   - Tier 0: `root@pam` break-glass only
   - Tier 1: named `@pam` users with shell access, optionally SSH and/or sudo (small, documented group)
   - Tier 2: named users with PBS RBAC (GUI/API, no shell)

- Root account and SSH handling:
   - Disable root SSH password authentication. Prefer key-based access only.
   - If you run a cluster, restrict root SSH to required cluster networks (see [1.1.1 CIS deviation](#111-apply-debian-13-cis-level-1)).

- Sudoers design patterns:
   - Grant sudo only when needed and only to Tier 1 OS shell admins.
   - Document who has sudo rights and review it regularly.
   - Optionally define fine-grained sudo roles (for example, read-only diagnostics vs OS maintenance).

- Decide when OS shell access is allowed:
   - If the task can be done via GUI/API, use Tier 2 RBAC and do not use SSH.
   - If the task requires host OS changes (packages, kernel, drivers, filesystem repair), use SSH as Tier 1 and elevate via sudo when needed.
   - If the task is emergency recovery, use Tier 1/0 break-glass access.

- Audit and logging:
   - Forward GUI/API access logs to centralized logging (see [5.1.1](#511-centralized-logging)).
   - Enforce sudo logging and forward sudo logs to centralized logging.
   - Keep `/etc/proxmox-backup` auditd coverage (see [5.1.2](#512-auditd-for-etcproxmox-backup)).

- API tokens:
   - Use dedicated service users and API tokens for automation (no shared credentials).
   - Scope ACLs to the minimum required paths and permissions.
   - Set expiration and rotate tokens regularly.
   - Never use `root@pam` API tokens for automation.
   - See [2.2 API Tokens](#22-api-tokens) for details.
   - **See [2.2 API Tokens](#22-api-tokens) for details.**

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

- `proxmox-backup-manager user generate-token <<alice@pbs client1 --expire 2026-12-31>>`
- Assign ACL on `<</datastore/store1>>` if the application should access only that datastore.
   - `proxmox-backup-manager acl update <</datastore/store1>> <<DatastoreAdmin>> --auth-id <<alice@pbs>>`
- Review assignments quarterly.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 2.2.2 Grant Least Privilege to Tokens

**Level 1**

**Description**\
Minimizes damage if a token leaks.

**Measures**

- Use roles such as `DatastoreAdmin` rather than `Admin`.
   - `proxmox-backup-manager acl update <</datastore>> <<DatastoreAdmin>> --auth-id <<alice@pbs>>`
- Review assignments quarterly.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 2.2.3 Store Tokens Securely

**Level 1**

**Description**\
Prevents plaintext exposure of secrets in scripts or CI logs.

**Measures**

- Store secrets in HashiCorp Vault, CyberArk, Bitwarden, **or a similar** vault solution.
- Never commit tokens to Git or other version-control systems.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 2.2.4 Rotate Tokens Regularly

**Level 1**

**Description**\
Limits lifetime of compromised tokens.

**Measures**

- Set `--expire` when creating tokens.
- Rotate every 365 days.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

#### 2.3 GUI

##### 2.3.1 Install Trusted Certificates

**Level 1**

**Description**\
Eliminates man-in-the-middle (MITM) risk and browser warnings by replacing each node’s default self-signed certificate
with a certificate issued by an internal CA or Let’s Encrypt.

**Measures**

1. Navigate to `Configuration --> Certificates --> Certificates` and upload the full-chain PEM certificate with its private key.
2. Prefer ACME/Let’s Encrypt for automated issuance, see [2.3.2 Automate Certificate Renewal](#232-automate-certificate-renewal).

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 2.3.2 Automate Certificate Renewal

**Level 1**

**Description**\
Prevents expired-cert outages.

**Measures**

1. **Register an ACME account** under `Configuration --> Certificates --> ACME Accounts`.
   - `proxmox-backup-manager acme account register <<default OR account-name>> <<mail@example.com>> <<--directory=http://Your-ACME.com>>`
2. If you are using the DNS-01 challenge, configure the required plugin.
   - `proxmox-backup-manager acme plugin add <<plugin‑name>> <<OPTIONS>>`
3. Add the server's FQDN under `Configuration --> Certificates --> Certificates`.
   - `proxmox-backup-manager node update --acmedomain0 https://<<pbs.example.com>>`
4. Click **Order Certificate** in the GUI to request and install the certificate.
   - `proxmox-backup-manager acme cert order`

> [!TIP]
> See the PBS docs: [Certificate Management](https://pbs.proxmox.com/docs/sysadmin.html#certificate-management)

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

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
   port = 8007
   filter = proxmox-backup-server
   logpath = /var/log/proxmox-backup/api/auth.log
   maxretry = 3
   findtime = 2h
   bantime = 1h
   ```

- Create `/etc/fail2ban/filter.d/proxmox-backup-server.conf` (or another appropriate file):

   ```ini
   [Definition]
   failregex = authentication failure; rhost=\[<HOST>\]:\d+ user=.* msg=.*
   ignoreregex =
   ```

- Restart fail2ban `systemctl restart fail2ban`
- Check fail2ban status:
   - `fail2ban-client status`
   - `fail2ban-client status sshd`
   - `fail2ban-client status proxmox`

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

### 3 Datastore Protections

##### 3.1 Turn On “verify-new”

**Level 1**

**Description**\
Forces an **immediate checksum comparison** after every chunk upload.
A snapshot is marked OK only if all blocks match their expected SHA-256 hashes, catching transmission errors or bad sectors before the job completes.

**Measures**

- `Datastore --> Options`: **Verify New Backups = Yes**
   - `proxmox-backup-manager datastore update <<datastore>> --verify-new true`

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 3.2 Schedule Weekly Verify Job

**Level 1**

**Description**\
Runs a full store scan to **detect silent bit-rot** or latent disk errors on previously verified snapshots.
Any corrupted chunk is flagged so it can be healed from another replica or a fresh backup.

**Measures**

- `Datastore --> Verify Jobs` Add:
   - **Schedule:** `<<sat 18:15>>` (pick a low-traffic window)
- `proxmox-backup-manager verify-job create <<ID>> --store <<datastore>> --schedule <<18:15>>`

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 3.3 Set Prune Policy

**Level 1**

**Description**\
Removes obsolete snapshots according to your **retention objectives**, keeping space usage predictable and recovery points relevant.

**Measures**

- `Datastore --> Prune & GC` Prune Jobs -> Add:
   - **Prune Schedule**: `<<22:30>>`
   - keep-last: `3`
   - keep-daily: `7`
   - keep-weekly: `4`
   - keep-monthly: `3`
- `proxmox-backup-manager prune-job create <<ID>> --schedule <<22:30>> --store <<datastore>> --keep-last <<3>> --keep-daily <<3>> --keep-weekly <<4>> --keep-monthly <<3>>`

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 3.4 Schedule Garbage Collection

**Level 1**

**Description**\
Reclaims disk space by deleting **unreferenced chunks** left behind after pruning. Must run **after** each prune cycle to be effective.

**Measures**

- `Datastore --> Prune & GC` Garbage Collect Jobs -> Edit:
   - **GC Schedule:** `<<23:00>>` (~30 min after prune)
- `proxmox-backup-manager datastore update <<datastore>> --gc-schedule <<23:00>>`

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 3.5 Alert on Verify, Sync, Prune & GC Errors

**Level 1**

**Description**\
Sends an email whenever a **verify, sync, prune, or GC job** exits with errors, ensuring operators can investigate before data loss accumulates.

**Measures**

- Configure `Datastore --> Options` Notify Edit:
   - Verification Jobs: `Errors`
   - Sync Jobs: `Errors`
   - Prune Jobs: `Errors`
   - Garbage Collection Jobs: `Errors`
- `proxmox-backup-manager datastore update <<datastore>> --notify verify=error`
- `proxmox-backup-manager datastore update <<datastore>> --notify sync=error`
- `proxmox-backup-manager datastore update <<datastore>> --notify prune=error`
- `proxmox-backup-manager datastore update <<datastore>> --notify gc=error`

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 3.6 Configure Re-Verify After

**Level 1**

**Description**\
Set a maximum age after which snapshots must be re-verified, even if they passed verification before.
This provides periodic end-to-end integrity checks to detect latent corruption.

**Measures**

- **GUI**: `Datastore --> Verify Jobs --> Edit` set **Re-verify after** to `<<60d>>` for general-purpose stores. Use `30d` for high-risk data or `90d` for very large stores.
   - `proxmox-backup-manager verify-job update <<ID>> --outdated-after <<60>>`

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 3.7 Remote Sync Jobs

**Level 1**

**Description**\
Replicate snapshots to a remote PBS to satisfy 3-2-1 and enable recovery even if the primary PBS is lost.

**Measures**

1. **Create a Remote** pointing to the destination server:
   - **GUI**: `Configuration --> Remotes --> Add`. Provide the destination API host, user or API token, and host certificate fingerprint. Test the connection.
   - `proxmox-backup-manager remote create <<remotename>> --auth-id <<string>> --host <<string>> --password <<string>> <<--comment <<remote1>> --fingerprint <<abcd>> --port <<8007>>>>`
2. **Create Sync Jobs** per datastore or namespace:
   - **GUI**: `Datastore --> Sync Jobs --> Add`.
   - Choose **Remote**, **Remote Datastore**, optional **Namespace**, and the local **Target Datastore**.
   - Schedule for off-peak hours. Consider a bandwidth **limit** if WAN constrained.
   - Leave **remove-vanished: false** unless you fully understand the implications of destructive syncs.
   - `proxmox-backup-manager sync-job create <<ID>> --remote-store <<remotename>> --store <<datastore>> --schedule <<3:00>> <<--ns <<namespace>> --remote-ns <<namespace>> --rate-in <<value>> --rate-out <<value>>>>`

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

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

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 4.2 Backup Host Configuration

##### 4.2.1 Backup Host Configuration

**Level 1**

**Description**\
Backs up the entire Proxmox Backup Server host configuration to a **second** Backup Server. A fresh install can be restored even if the primary PBS is unavailable.

**Measures**

1. **Verify the client is present**:

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
                --include-dev /boot
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

4. Verify restores quarterly: `proxmox-backup-client restore pbsconf.pxar /tmp/pbs-restore --verify`

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 4.2.2 Encrypt Host Configuration Backups

**Level 2**

**Description**\
Encrypts the host-configuration archives **before** they leave the PBS Node.
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
In the PBS UI or via CLI, confirm the backup shows as encrypted.

> [!NOTE]
> Key management is critical: escrow a copy, document recovery, and restrict file permissions (600, root-owned).
> Rotate keys on a planned schedule; re-encrypt old backups only if policy requires.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

### 5 Logging, Monitoring, Auditing & Documentation

#### 5.1 Logging

##### 5.1.1 Centralized Logging

**Level 1**

**Description**\
Provides tamper-evident storage and allows for correlation of security events.

**Measures**

In **addition** to *CIS Debian 13 Benchmark § 6.1*, forward:

- `/var/log/proxmox-backup/api/access.log`
- `/var/log/proxmox-backup/api/auth.log`

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

##### 5.1.2 Auditd for /etc/proxmox-backup

**Level 2**

**Description**\
Tracks configuration changes in the proxmox-backup files.

**Measures**

- Create a **persistent** audit rule file:

  `/etc/audit/rules.d/90-pbs.rules`

  ```ini
  -w /etc/proxmox-backup -p wa -k pbs-config
  ```

- Load rules and verify:
   - `augenrules --load`, rebuild /etc/audit/audit.rules from rules.d
   - `systemctl restart auditd`, **alternative** reload if augenrules is not present
   - `auditctl -l | grep pbs-config`, should list the /etc/proxmox-backup watch
   - `ausearch -k pbs-config`, view matching audit events

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

#### 5.2 Monitoring

##### 5.2.1 Centralized Metrics

**Level 1**

**Description**\
Detects capacity issues before they become outages.

**Measures**

- Example:
   - Export to Prometheus with `pve_exporter`.
   - Dashboards in Grafana.

> [!NOTE]
> Or another **appropriate** monitoring solution.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

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

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

#### 5.3 Auditing

##### 5.3.1 System Audits

**Level 2**

**Description**\
Objective measurement of compliance drift over time.

**Measures**

- Run OpenSCAP or other quarterly **and** after major upgrades.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

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

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

---

#### 5.4 Documentation

**Level 1**

**Description**\
Maintains institutional knowledge and supports audits.

**Measures**

- Update network diagrams, inventory, and change logs after ***every** significant change.

**Execution Status**

- [ ] YES - Control implemented
- [ ] NO  - Control not implemented

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
- name: Harden PBS
  hosts: pbs
  become: true
  tasks:
```

- HomeSecExplorer *ansible-role-sshaudit* role

`ansible-galaxy install HomeSecExplorer.sshaudit`

```yaml
- name: Run HomeSecExplorer ansible-role-sshaudit
  ansible.builtin.include_role:
    name: "HomeSecExplorer.sshaudit"
  vars:
    hsesa_ssh_audit_package_state: absent
    hsesa_ssh_audit_test: false
    hsesa_regenerate_ssh_host_keys: false
```

- HomeSecExplorer *ansible-role-autoupdate* role

`ansible-galaxy install HomeSecExplorer.autoupdate`

```yaml
- name: Run HomeSecExplorer ansible-role-autoupdate
  ansible.builtin.include_role:
    name: "HomeSecExplorer.autoupdate"
```

### C. Recovery-Drill Checklist

1. Start-of-year cold test: Restore the most recent nightly backup to an isolated lab and boot VMs.
2. Quarterly file-level restore test: Restore on a single VM disk.
3. Document outcomes, time-to-recover, and update runbooks.

### D. Installation checklists Host

- [ ] Firmware, IPMI and BIOS updated
- [ ] Prepare Network segmentation
- [ ] Install Debian with correct partitioning
- [ ] Execute Hardening Guide
- [ ] Create/Update documentation

---

## Change Notes

| Version | Date       | Author              | Key Changes                                    | Reviewed By |
|---------|------------|---------------------|------------------------------------------------|-------------|
| 0.9.0   | 2025-12-30 | HomeSecExplorer     | Initial creation.                              |   --------  |
| 0.9.1   | 2026-01-12 | HomeSecExplorer     | added: 2.1.5, Design principles                |   --------  |
