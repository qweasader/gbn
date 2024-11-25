# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0036");
  script_cve_id("CVE-2019-19037");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-22 16:15:47 +0000 (Fri, 22 Nov 2019)");

  script_name("Mageia: Security Advisory (MGASA-2020-0036)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0036");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0036.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25882");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25930");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25982");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26003");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26015");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26049");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.4.10");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.4.7");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.4.8");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.4.9");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kmod-virtualbox, kmod-xtables-addons, wireguard-tools' package(s) announced via the MGASA-2020-0036 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update is based on upstream 5.4.10 and fixes at least the following
security issues:

ext4_empty_dir in fs/ext4/namei.c in the Linux kernel through 5.3.12 allows
a NULL pointer dereference because ext4_read_dirblock(inode,0,DIRENT_HTREE)
can be zero. (CVE-2019-19037)

It also fixes various potential security issues related to buffer overflows,
double frees, NUll pointer dereferences, improper / missing input
validations and so on.

Other fixes added in this update:
- Revert 'drm/amdgpu: Set no-retry as default.', fixing amdgpu hang
 on Raven Ridge gpus (mga#25882)
- drm/i915/gt: Detect if we miss WaIdleLiteRestore, fixes or at least
 works around gpu hang (mga#25930)
- 3rdparty/rtl8812au: update to v5.6.4.2 (mga#25982)
- add support for RTL8117 ethernet
- rtl8xxxu: Add support for Edimax EW-7611ULB
- mountpoint_last(): fix the treatment of LAST_BIND
- HID: intel-ish-hid: ipc: Add Comet Lake H PCI device ID
- HID: intel-ish-hid: ipc: Add Tiger Lake PCI device ID
- HID: wacom: Recognize new MobileStudio Pro PID
- updates to the arm64 defconfigs:
 - Enable some EFI stuff on arm64 (mga#26003)
 - Enable a lot of missing things on arm64 kernels (including ACPI
 and Amazon network driver)
 - Disable debug info on arm64 (mga#26015)
 - reduce difference between arm64 and x86_64 defconfigs

WireGuard kernel module has been updated to 0.0.20200105 and the tools
has been updated to 1.0.20200102.

For other fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel, kmod-virtualbox, kmod-xtables-addons, wireguard-tools' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-5.4.10-1.mga7", rpm:"kernel-desktop-5.4.10-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-5.4.10-1.mga7", rpm:"kernel-desktop-devel-5.4.10-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-5.4.10-1.mga7", rpm:"kernel-desktop586-5.4.10-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-5.4.10-1.mga7", rpm:"kernel-desktop586-devel-5.4.10-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-5.4.10-1.mga7", rpm:"kernel-server-5.4.10-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-5.4.10-1.mga7", rpm:"kernel-server-devel-5.4.10-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-5.4.10-1.mga7", rpm:"kernel-source-5.4.10-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.0.14~18.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~3.7~8.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf-devel", rpm:"lib64bpf-devel~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf0", rpm:"lib64bpf0~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf-devel", rpm:"libbpf-devel~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf0", rpm:"libbpf0~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~5.4.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.4.10-desktop-1.mga7", rpm:"virtualbox-kernel-5.4.10-desktop-1.mga7~6.0.14~18.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.4.10-desktop586-1.mga7", rpm:"virtualbox-kernel-5.4.10-desktop586-1.mga7~6.0.14~18.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.4.10-server-1.mga7", rpm:"virtualbox-kernel-5.4.10-server-1.mga7~6.0.14~18.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.0.14~18.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~6.0.14~18.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.0.14~18.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireguard-tools", rpm:"wireguard-tools~1.0.20200102~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.4.10-desktop-1.mga7", rpm:"xtables-addons-kernel-5.4.10-desktop-1.mga7~3.7~8.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.4.10-desktop586-1.mga7", rpm:"xtables-addons-kernel-5.4.10-desktop586-1.mga7~3.7~8.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.4.10-server-1.mga7", rpm:"xtables-addons-kernel-5.4.10-server-1.mga7~3.7~8.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~3.7~8.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~3.7~8.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~3.7~8.mga7", rls:"MAGEIA7"))) {
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
