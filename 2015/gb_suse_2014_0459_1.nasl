# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850750");
  script_version("2020-08-31T07:00:15+0000");
  script_tag(name:"last_modification", value:"2020-08-31 07:00:15 +0000 (Mon, 31 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:00 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2013-4470", "CVE-2013-6885", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2014-0069");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for Linux (SUSE-SU-2014:0459-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 Service Pack 3 kernel was
  updated to fix  various bugs and security issues.

  WARNING: If you are running KVM with PCI
  pass-through on a system with one  of the following Intel
  chipsets: 5500 (revision 0x13), 5520 (revision 0x13)  or
  X58 (revisions 0x12, 0x13, 0x22), please make sure to read
  the following referenced support document before installing this
  update. You will have to update your KVM setup to no longer make use
  of PCI pass-through before  rebooting to the updated
  kernel.

  The following security bugs were fixed:

  * CVE-2013-4470: The Linux kernel before 3.12, when UDP
  Fragmentation Offload (UFO) is enabled, does not properly
  initialize certain data structures, which allows local
  users to cause a denial of service (memory corruption and
  system crash) or possibly gain privileges via a crafted
  application that uses the UDP_CORK option in a setsockopt
  system call and sends both short and long packets, related
  to the ip_ufo_append_data function in net/ipv4/ip_output.c
  and the ip6_ufo_append_data function in
  net/ipv6/ip6_output.c. (bnc#847672)

  * CVE-2013-6885: The microcode on AMD 16h 00h through
  0Fh processors does not properly handle the interaction
  between locked instructions and write-combined memory
  types, which allows local users to cause a denial of
  service (system hang) via a crafted application, aka the
  errata 793 issue. (bnc#852967)

  * CVE-2013-7263: The Linux kernel before 3.12.4 updates
  certain length values before ensuring that associated data
  structures have been initialized, which allows local users
  to obtain sensitive information from kernel stack memory
  via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system
  call, related to net/ipv4/ping.c, net/ipv4/raw.c,
  net/ipv4/udp.c, net/ipv6/raw.c, and net/ipv6/udp.c.
  (bnc#857643)

  * CVE-2013-7264: The l2tp_ip_recvmsg function in
  net/l2tp/l2tp_ip.c in the Linux kernel before 3.12.4
  updates a certain length value before ensuring that an
  associated data structure has been initialized, which
  allows local users to obtain sensitive information from
  kernel stack memory via a (1) recvfrom, (2 ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_xref(name:"URL", value:"https://www.suse.com/support/kb/doc.php?id=7014344");

  script_tag(name:"affected", value:"Linux on SUSE Linux Enterprise Server 11 SP3");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2014:0459-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP3") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.4_02_3.0.101_0.18~0.7.5", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.4_02_3.0.101_0.18~0.7.5", rls:"SLES11.0SP3"))) {
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
