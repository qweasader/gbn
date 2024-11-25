# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0324");
  script_cve_id("CVE-2018-10840", "CVE-2018-1087", "CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10879", "CVE-2018-10880", "CVE-2018-10881", "CVE-2018-10882", "CVE-2018-10883", "CVE-2018-1118", "CVE-2018-11412", "CVE-2018-13405", "CVE-2018-8897");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-20 14:00:15 +0000 (Wed, 20 Jun 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0324)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0324");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0324.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23263");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23305");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23315");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.51");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.52");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.53");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.54");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.55");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.56");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kernel-userspace-headers, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons, wireguard-tools' package(s) announced via the MGASA-2018-0324 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update is based on the upstream 4.14.56 and fixes at least
the following security issues:

kernel KVM before versions kernel 4.16, kernel 4.16-rc7, kernel 4.17-rc1,
kernel 4.17-rc2 and kernel 4.17-rc3 is vulnerable to a flaw in the way the
Linux kernel's KVM hypervisor handled exceptions delivered after a stack
switch operation via Mov SS or Pop SS instructions. During the stack switch
operation, the processor did not deliver interrupts and exceptions, rather
they are delivered once the first instruction after the stack switch is
executed. An unprivileged KVM guest user could use this flaw to crash the
guest or, potentially, escalate their privileges in the guest
(CVE-2018-1087).

Linux kernel vhost since version 4.8 does not properly initialize memory in
messages passed between virtual guests and the host operating system in the
vhost/vhost.c:vhost_new_msg() function. This can allow local privileged
users to read some kernel memory contents when reading from the
/dev/vhost-net device file (CVE-2018-1118).

In some circumstances, some operating systems or hypervisors may not expect
or properly handle an Intel architecture hardware debug exception. The error
appears to be due to developer interpretation of existing documentation for
certain Intel architecture interrupt/exception instructions, namely MOV SS
and POP SS. An authenticated attacker may be able to read sensitive data in
memory or control low-level operating system functions (CVE-2018-8897).

Linux kernel is vulnerable to a heap-based buffer overflow in the
fs/ext4/xattr.c:ext4_xattr_set_entry() function. An attacker could exploit
this by operating on a mounted crafted ext4 image (CVE-2018-10840).

A flaw was found in Linux kernel ext4 File System. A use-after-free in
ext4_ext_remove_space() when mounting and operating a crafted ext4 image
(CVE-2018-10876).

Linux kernel ext4 filesystem is vulnerable to an out-of-bound access in the
ext4_ext_drop_refs() function when operating on a crafted ext4 filesystem
image (CVE-2018-10877).

A flaw was found in Linux kernel ext4 filesystem. A local user can cause a
use-after-free in ext4_xattr_set_entry function and so a denial of service
or possibly unspecified other impact by when renaming a file in a crafted
ext4 filesystem image (CVE-2018-10879).

A flaw was found in Linux kernel ext4 filesystem code. A stack-out-of-bounds
write in ext4_update_inline_data() is possible when mounting and writing to
a crafted ext4 image. An attacker could use this to cause a system crash
and a denial of service (CVE-2018-10880).

A flaw was found in Linux kernel ext4 filesystem. A local user can cause an
out-of-bound access in ext4_get_group_info function and so a denial of
service and a system crash by mounting and operating on a crafted ext4
filesystem image (CVE-2018-10881).

A flaw was found in Linux kernel ext4 File System. An out-of-bound write
when unmounting a crafted ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, kernel-userspace-headers, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons, wireguard-tools' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~4.14.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~4.14.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.14.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-4.14.56-1.mga6", rpm:"kernel-desktop-4.14.56-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-armv6v7-4.14.56-1.mga6", rpm:"kernel-desktop-armv6v7-4.14.56-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-armv6v7-devel-4.14.56-1.mga6", rpm:"kernel-desktop-armv6v7-devel-4.14.56-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-armv6v7-devel-latest", rpm:"kernel-desktop-armv6v7-devel-latest~4.14.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-armv6v7-latest", rpm:"kernel-desktop-armv6v7-latest~4.14.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-4.14.56-1.mga6", rpm:"kernel-desktop-devel-4.14.56-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~4.14.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~4.14.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-4.14.56-1.mga6", rpm:"kernel-desktop586-4.14.56-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-4.14.56-1.mga6", rpm:"kernel-desktop586-devel-4.14.56-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~4.14.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~4.14.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~4.14.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-4.14.56-1.mga6", rpm:"kernel-server-4.14.56-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-4.14.56-1.mga6", rpm:"kernel-server-devel-4.14.56-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~4.14.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~4.14.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-4.14.56-1.mga6", rpm:"kernel-source-4.14.56-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~4.14.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~4.14.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~5.2.14~6.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~5.2.14~6.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~2.13~48.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.14.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.56-desktop-1.mga6", rpm:"vboxadditions-kernel-4.14.56-desktop-1.mga6~5.2.14~6.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.56-desktop586-1.mga6", rpm:"vboxadditions-kernel-4.14.56-desktop586-1.mga6~5.2.14~6.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.56-server-1.mga6", rpm:"vboxadditions-kernel-4.14.56-server-1.mga6~5.2.14~6.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~5.2.14~6.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~5.2.14~6.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~5.2.14~6.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.56-desktop-1.mga6", rpm:"virtualbox-kernel-4.14.56-desktop-1.mga6~5.2.14~6.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.56-desktop586-1.mga6", rpm:"virtualbox-kernel-4.14.56-desktop586-1.mga6~5.2.14~6.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.56-server-1.mga6", rpm:"virtualbox-kernel-4.14.56-server-1.mga6~5.2.14~6.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~5.2.14~6.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~5.2.14~6.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~5.2.14~6.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireguard-tools", rpm:"wireguard-tools~0.0.20180708~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-4.14.56-desktop-1.mga6", rpm:"xtables-addons-kernel-4.14.56-desktop-1.mga6~2.13~48.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-4.14.56-desktop586-1.mga6", rpm:"xtables-addons-kernel-4.14.56-desktop586-1.mga6~2.13~48.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-4.14.56-server-1.mga6", rpm:"xtables-addons-kernel-4.14.56-server-1.mga6~2.13~48.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~2.13~48.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~2.13~48.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~2.13~48.mga6", rls:"MAGEIA6"))) {
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
