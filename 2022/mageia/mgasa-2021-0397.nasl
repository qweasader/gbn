# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0397");
  script_cve_id("CVE-2021-34556", "CVE-2021-35477");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-10 03:15:00 +0000 (Tue, 10 Aug 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0397)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0397");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0397.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29311");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29262");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29285");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.53");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.54");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.55");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.56");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2021-0397 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update is based on upstream 5.10.56 and fixes at least the
following security issues:

In the Linux kernel through 5.13.7, an unprivileged BPF program can
obtain sensitive information from kernel memory via a Speculative Store
Bypass side-channel attack because the protection mechanism neglects the
possibility of uninitialized memory locations on the BPF stack
(CVE-2021-34556).

In the Linux kernel through 5.13.7, an unprivileged BPF program can
obtain sensitive information from kernel memory via a Speculative Store
Bypass side-channel attack because a certain preempting store operation
does not necessarily occur before a store operation that has an
attacker-controlled value (CVE-2021-35477).

Other fixes in this update:
- btrfs: fix lost inode on log replay after mix of fsync, rename and
 inode eviction
- btrfs: fix race causing unnecessary inode logging during link and rename
- watchdog: iTCO_wdt: Fix detection of SMI-off case (fixes sporadic reboots
 on some systems)
- Revert 'ACPICA: Fix memory leak caused by _CID repair function', fixing
 boot failures on some systems
- fix another ACPI issue causing some systems to boot slowly or not at all
 after kernel 5.10.50
- revert: 'scsi: sr: Return appropriate error code when disk is ejected'
 (fixes DVD opening on resume from suspend or standby, mga #29262)
- Revert 'usb: renesas-xhci: Fix handling of unknown ROM state'
 (fixes renesas usb pci stopped working, mga #29285)
- Revert 'drm/i915: Propagate errors on awaiting already signaled fences'
 and 'drm/i915/gem: Asynchronous cmdparser' (fixes an issue where an
 app hang can cause X server to hang)

For other upstream fixes, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-5.10.56-1.mga8", rpm:"kernel-desktop-5.10.56-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-5.10.56-1.mga8", rpm:"kernel-desktop-devel-5.10.56-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-5.10.56-1.mga8", rpm:"kernel-desktop586-5.10.56-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-5.10.56-1.mga8", rpm:"kernel-desktop586-devel-5.10.56-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-5.10.56-1.mga8", rpm:"kernel-server-5.10.56-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-5.10.56-1.mga8", rpm:"kernel-server-devel-5.10.56-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-5.10.56-1.mga8", rpm:"kernel-source-5.10.56-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.1.24~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~3.18~1.16.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf-devel", rpm:"lib64bpf-devel~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf0", rpm:"lib64bpf0~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf-devel", rpm:"libbpf-devel~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf0", rpm:"libbpf0~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~5.10.56~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.10.56-desktop-1.mga8", rpm:"virtualbox-kernel-5.10.56-desktop-1.mga8~6.1.24~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.10.56-server-1.mga8", rpm:"virtualbox-kernel-5.10.56-server-1.mga8~6.1.24~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.1.24~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.1.24~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.10.56-desktop-1.mga8", rpm:"xtables-addons-kernel-5.10.56-desktop-1.mga8~3.18~1.16.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.10.56-desktop586-1.mga8", rpm:"xtables-addons-kernel-5.10.56-desktop586-1.mga8~3.18~1.16.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.10.56-server-1.mga8", rpm:"xtables-addons-kernel-5.10.56-server-1.mga8~3.18~1.16.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~3.18~1.16.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~3.18~1.16.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~3.18~1.16.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
