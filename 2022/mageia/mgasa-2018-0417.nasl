# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0417");
  script_cve_id("CVE-2018-14633", "CVE-2018-15471", "CVE-2018-18281", "CVE-2018-18445", "CVE-2018-7755");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-17 21:34:00 +0000 (Tue, 17 Jan 2023)");

  script_name("Mageia: Security Advisory (MGASA-2018-0417)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0417");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0417.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23687");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.71");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.72");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.73");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.74");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.75");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.76");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.77");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.78");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kernel-userspace-headers, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons, wireguard-tools' package(s) announced via the MGASA-2018-0417 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update is based on the upstream 4.14.78 and fixes at least the
following security issues:

An issue was discovered in the fd_locked_ioctl function in
drivers/block/floppy.c in the Linux kernel through 4.15.7. The floppy
driver will copy a kernel pointer to user memory in response to the
FDGETPRM ioctl. An attacker can send the FDGETPRM ioctl and use the
obtained kernel pointer to discover the location of kernel code and data
and bypass kernel security protections such as KASLR (CVE-2018-7755).

A security flaw was found in the chap_server_compute_md5() function in the
ISCSI target code in the Linux kernel in a way an authentication request
from an ISCSI initiator is processed. An unauthenticated remote attacker
can cause a stack buffer overflow and smash up to 17 bytes of the stack.
The attack requires the iSCSI target to be enabled on the victim host.
Depending on how the target's code was built (i.e. depending on a compiler,
compile flags and hardware architecture) an attack may lead to a system
crash and thus to a denial-of-service or possibly to a non-authorized
access to data exported by an iSCSI target. Due to the nature of the flaw,
privilege escalation cannot be fully ruled out, although we believe it is
highly unlikely (CVE-2018-14633).

An issue was discovered in xenvif_set_hash_mapping in
drivers/net/xen-netback/hash.c in the Linux kernel through 4.18.1, as used
in Xen through 4.11.x and other products. The Linux netback driver allows
frontends to control mapping of requests to request queues. When processing
a request to set or change this mapping, some input validation (e.g., for
an integer overflow) was missing or flawed, leading to OOB access in hash
handling. A malicious or buggy frontend may cause the (usually privileged)
backend to make out of bounds memory accesses, potentially resulting in
one or more of privilege escalation, Denial of Service (DoS), or
information leaks (CVE-2018-15471).

Since Linux kernel version 3.2, the mremap() syscall performs TLB flushes
after dropping pagetable locks. If a syscall such as ftruncate() removes
entries from the pagetables of a task that is in the middle of mremap(),
a stale TLB entry can remain for a short time that permits access to a
physical page after it has been released back to the page allocator and
reused (CVE-2018-18281).

In the Linux kernel 4.14.x, 4.15.x, 4.16.x, 4.17.x, and 4.18.x before
4.18.13, faulty computation of numeric bounds in the BPF verifier permits
out-of-bounds memory accesses because adjust_scalar_min_max_vals in
kernel/bpf/verifier.c mishandles 32-bit right shifts (CVE-2018-18445).

Other fixes in this update:
* WireGuard has been updated 0.0.20181018

For other uptstream fixes in this update, see the referenced changelogs.");

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

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-4.14.78-1.mga6", rpm:"kernel-desktop-4.14.78-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-armv6v7-4.14.78-1.mga6", rpm:"kernel-desktop-armv6v7-4.14.78-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-armv6v7-devel-4.14.78-1.mga6", rpm:"kernel-desktop-armv6v7-devel-4.14.78-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-armv6v7-devel-latest", rpm:"kernel-desktop-armv6v7-devel-latest~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-armv6v7-latest", rpm:"kernel-desktop-armv6v7-latest~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-4.14.78-1.mga6", rpm:"kernel-desktop-devel-4.14.78-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-4.14.78-1.mga6", rpm:"kernel-desktop586-4.14.78-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-4.14.78-1.mga6", rpm:"kernel-desktop586-devel-4.14.78-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-4.14.78-1.mga6", rpm:"kernel-server-4.14.78-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-4.14.78-1.mga6", rpm:"kernel-server-devel-4.14.78-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-4.14.78-1.mga6", rpm:"kernel-source-4.14.78-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~5.2.18~10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~5.2.18~10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~2.13~70.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.78-desktop-1.mga6", rpm:"vboxadditions-kernel-4.14.78-desktop-1.mga6~5.2.18~10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.78-desktop586-1.mga6", rpm:"vboxadditions-kernel-4.14.78-desktop586-1.mga6~5.2.18~10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.14.78-server-1.mga6", rpm:"vboxadditions-kernel-4.14.78-server-1.mga6~5.2.18~10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~5.2.18~10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~5.2.18~10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~5.2.18~10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.78-desktop-1.mga6", rpm:"virtualbox-kernel-4.14.78-desktop-1.mga6~5.2.18~10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.78-desktop586-1.mga6", rpm:"virtualbox-kernel-4.14.78-desktop586-1.mga6~5.2.18~10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.14.78-server-1.mga6", rpm:"virtualbox-kernel-4.14.78-server-1.mga6~5.2.18~10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~5.2.18~10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~5.2.18~10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~5.2.18~10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireguard-tools", rpm:"wireguard-tools~0.0.20181018~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-4.14.78-desktop-1.mga6", rpm:"xtables-addons-kernel-4.14.78-desktop-1.mga6~2.13~70.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-4.14.78-desktop586-1.mga6", rpm:"xtables-addons-kernel-4.14.78-desktop586-1.mga6~2.13~70.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-4.14.78-server-1.mga6", rpm:"xtables-addons-kernel-4.14.78-server-1.mga6~2.13~70.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~2.13~70.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~2.13~70.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~2.13~70.mga6", rls:"MAGEIA6"))) {
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
