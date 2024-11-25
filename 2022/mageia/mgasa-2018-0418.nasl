# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0418");
  script_cve_id("CVE-2018-14633", "CVE-2018-14641", "CVE-2018-15471", "CVE-2018-17182", "CVE-2018-18281", "CVE-2018-18445", "CVE-2018-5391", "CVE-2018-7755");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-06 14:29:55 +0000 (Thu, 06 Dec 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0418)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0418");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0418.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23688");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.70");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.71");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.72");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.73");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.74");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.75");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.76");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.77");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.78");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2018-0418 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-tmb update is based on the upstream 4.14.78 and adds additional
fixes for the L1TF security issues. It also fixes at least the following
security issues:

Linux kernel from versions 3.9 and up, is vulnerable to a denial of
service attack with low rates of specially modified packets targeting IP
fragment re-assembly. An attacker may cause a denial of service condition
by sending specially crafted IP fragments (CVE-2018-5391, FragmentSmack).

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

A security flaw was found in the ip_frag_reasm() function in
net/ipv4/ip_fragment.c in the Linux kernel caused by fixes for
CVE-2018-5391, which can cause a later system crash in ip_do_fragment().
With certain non-default, but non-rare, configuration of a victim host,
an attacker can trigger this crash remotely, thus leading to a remote
denial-of-service (CVE-2018-14641).

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

An issue was discovered in the Linux kernel through 4.18.8. The
vmacache_flush_all function in mm/vmacache.c mishandles sequence number
overflows. An attacker can trigger a use-after-free (and possibly gain
privileges) via certain thread ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-4.14.78-1.mga6", rpm:"kernel-tmb-desktop-4.14.78-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-4.14.78-1.mga6", rpm:"kernel-tmb-desktop-devel-4.14.78-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~4.14.78~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-4.14.78-1.mga6", rpm:"kernel-tmb-source-4.14.78-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~4.14.78~1.mga6", rls:"MAGEIA6"))) {
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
