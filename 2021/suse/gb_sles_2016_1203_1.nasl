# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1203.1");
  script_cve_id("CVE-2013-2015", "CVE-2013-7446", "CVE-2015-0272", "CVE-2015-7509", "CVE-2015-7515", "CVE-2015-7550", "CVE-2015-7566", "CVE-2015-7799", "CVE-2015-8215", "CVE-2015-8539", "CVE-2015-8543", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8569", "CVE-2015-8575", "CVE-2015-8767", "CVE-2015-8785", "CVE-2015-8812", "CVE-2015-8816", "CVE-2016-0723", "CVE-2016-2069", "CVE-2016-2143", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2188", "CVE-2016-2384", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549", "CVE-2016-2782", "CVE-2016-2847", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3139", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-3955");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:07 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-11-07T10:13:06+0000");
  script_tag(name:"last_modification", value:"2022-11-07 10:13:06 +0000 (Mon, 07 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-03 20:31:00 +0000 (Thu, 03 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1203-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1203-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161203-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:1203-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP3 kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2013-7446: Use-after-free vulnerability in net/unix/af_unix.c in the
 Linux kernel allowed local users to bypass intended AF_UNIX socket
 permissions or cause a denial of service (panic) via crafted epoll_ctl
 calls (bnc#955654).
- CVE-2015-7509: fs/ext4/namei.c in the Linux kernel allowed physically
 proximate attackers to cause a denial of service (system crash) via a
 crafted no-journal filesystem, a related issue to CVE-2013-2015
 (bnc#956707).
- CVE-2015-7515: An out of bounds memory access in the aiptek USB driver
 could be used by physical local attackers to crash the kernel
 (bnc#956708).
- CVE-2015-7550: The keyctl_read_key function in security/keys/keyctl.c in
 the Linux kernel did not properly use a semaphore, which allowed local
 users to cause a denial of service (NULL pointer dereference and system
 crash) or possibly have unspecified other impact via a crafted
 application that leverages a race condition between keyctl_revoke and
 keyctl_read calls (bnc#958951).
- CVE-2015-7566: A malicious USB device could cause kernel crashes in the
 visor device driver (bnc#961512).
- CVE-2015-7799: The slhc_init function in drivers/net/slip/slhc.c in the
 Linux kernel did not ensure that certain slot numbers are valid, which
 allowed local users to cause a denial of service (NULL pointer
 dereference and system crash) via a crafted PPPIOCSMAXCID ioctl call
 (bnc#949936).
- CVE-2015-8215: net/ipv6/addrconf.c in the IPv6 stack in the Linux kernel
 did not validate attempted changes to the MTU value, which allowed
 context-dependent attackers to cause a denial of service (packet loss)
 via a value that is (1) smaller than the minimum compliant value or (2)
 larger than the MTU of an interface, as demonstrated by a Router
 Advertisement (RA) message that is not validated by a daemon, a
 different vulnerability than CVE-2015-0272. NOTE: the scope of
 CVE-2015-0272 is limited to the NetworkManager product (bnc#955354).
- CVE-2015-8539: The KEYS subsystem in the Linux kernel allowed local
 users to gain privileges or cause a denial of service (BUG) via crafted
 keyctl commands that negatively instantiate a key, related to
 security/keys/encrypted-keys/encrypted.c, security/keys/trusted.c, and
 security/keys/user_defined.c (bnc#958463).
- CVE-2015-8543: The networking implementation in the Linux kernel did not
 validate protocol identifiers for certain protocol families, which
 allowed local users to cause a denial of service (NULL function pointer
 dereference and system crash) or possibly gain privileges by leveraging
 CLONE_NEWUSER support to execute a crafted SOCK_RAW application
 (bnc#958886).
- CVE-2015-8550: Optimizations introduced by the compiler could have lead
 to double fetch vulnerabilities, potentially possibly leading to
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Server 11, SUSE Linux Enterprise Server 11-SP3, SUSE Manager 2.1, SUSE Manager Proxy 2.1, SUSE OpenStack Cloud 5.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-extra", rpm:"kernel-bigsmp-extra~3.0.101~0.47.79.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~0.47.79.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~0.47.79.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~0.47.79.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~0.47.79.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~0.47.79.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-base", rpm:"kernel-bigsmp-base~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-devel", rpm:"kernel-bigsmp-devel~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.47.79.1", rls:"SLES11.0SP3"))) {
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
