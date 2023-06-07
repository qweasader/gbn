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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2776.1");
  script_cve_id("CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10880", "CVE-2018-10881", "CVE-2018-10882", "CVE-2018-10883", "CVE-2018-10902", "CVE-2018-10938", "CVE-2018-1128", "CVE-2018-1129", "CVE-2018-12896", "CVE-2018-13093", "CVE-2018-13094", "CVE-2018-13095", "CVE-2018-15572", "CVE-2018-16658", "CVE-2018-6554", "CVE-2018-6555", "CVE-2018-9363");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-01-23T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 16:01:00 +0000 (Thu, 19 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2776-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2776-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182776-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2776-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.155 to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2018-13093: Prevent NULL pointer dereference and panic in
 lookup_slow()
 on a NULL inode->i_ops pointer when doing pathwalks on a corrupted xfs
 image. This occurred because of a lack of proper validation that cached
 inodes are free during allocation (bnc#1100001).

CVE-2018-13095: Prevent denial of service (memory corruption and BUG)
 that could have occurred for a corrupted xfs image upon encountering an
 inode that is in extent format, but has more extents than fit in the
 inode fork (bnc#1099999).

CVE-2018-13094: Prevent OOPS that may have occurred for a corrupted xfs
 image after xfs_da_shrink_inode() is called with a NULL bp (bnc#1100000).

CVE-2018-12896: Prevent integer overflow in the POSIX timer code that
 was caused by the way the overrun accounting works. Depending on
 interval and expiry time values, the overrun can be larger than INT_MAX,
 but the accounting is int based. This basically made the accounting
 values, which are visible to user space via timer_getoverrun(2) and
 siginfo::si_overrun, random. This allowed a local user to cause a denial
 of service (signed integer overflow) via crafted mmap, futex,
 timer_create, and timer_settime system calls (bnc#1099922).

CVE-2018-16658: Prevent information leak in cdrom_ioctl_drive_status
 that could have been used by local attackers to read kernel memory
 (bnc#1107689).

CVE-2018-6555: The irda_setsockopt function allowed local users to cause
 a denial of service (ias_object use-after-free and system crash) or
 possibly have unspecified other impact via an AF_IRDA socket
 (bnc#1106511).

CVE-2018-6554: Prevent memory leak in the irda_bind function that
 allowed local users to cause a denial of service (memory consumption) by
 repeatedly binding an AF_IRDA socket (bnc#1106509).

CVE-2018-1129: A flaw was found in the way signature calculation was
 handled by cephx authentication protocol. An attacker having access to
 ceph cluster network who is able to alter the message payload was able
 to bypass signature checks done by cephx protocol (bnc#1096748).

CVE-2018-1128: It was found that cephx authentication protocol did not
 verify ceph clients correctly and was vulnerable to replay attack. Any
 attacker having access to ceph cluster network who is able to sniff
 packets on network can use this vulnerability to authenticate with ceph
 service and perform actions allowed by ceph service (bnc#1096748).

CVE-2018-10938: A crafted network packet sent remotely by an attacker
 forced the kernel to enter an infinite loop in the cipso_v4_optptr()
 function leading to a denial-of-service (bnc#1106016).

CVE-2018-15572: The spectre_v2_select_mitigation function did not always
 fill RSB upon a context switch, which made it easier for attackers to
 conduct ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE CaaS Platform 3.0, SUSE CaaS Platform ALL, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise High Availability 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
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
