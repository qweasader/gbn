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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0003.1");
  script_cve_id("CVE-2018-17963", "CVE-2018-18849", "CVE-2018-18883", "CVE-2018-19665", "CVE-2018-19961", "CVE-2018-19962", "CVE-2018-19963", "CVE-2018-19964", "CVE-2018-19965", "CVE-2018-19966", "CVE-2018-19967");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-14 15:00:00 +0000 (Thu, 14 May 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0003-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0003-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190003-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2019:0003-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:
Update to Xen 4.11.1 bug fix release (bsc#1027519)
CVE-2018-17963: Fixed an integer overflow issue in the QEMU emulator,
 which could occur when a packet with large packet size is processed. A
 user inside a guest could have used this flaw to crash the qemu process
 resulting in a Denial of Service (DoS). (bsc#1111014)

CVE-2018-18849: Fixed an out of bounds memory access in the LSI53C895A
 SCSI host bus adapter emulation, which allowed a user and/or process to
 crash the qemu process resulting in a Denial of Service (DoS).
 (bsc#1114423)

CVE-2018-18883: Fixed an issue related to inproper restriction of nested
 VT-x, which allowed a guest to cause Xen to crash, resulting in a Denial
 of Service (DoS). (XSA-278) (bsc#1114405)

CVE-2018-19961, CVE-2018-19962: Fixed an issue related to insufficient
 TLB flushing with AMD IOMMUs, which potentially allowed a guest to
 escalate its privileges, may cause a Denial of Service (DoS) affecting
 the entire host, or may be able to access data it is not supposed to
 access. (XSA-275) (bsc#1115040)

CVE-2018-19963: Fixed the allocation of pages used to communicate with
 external emulators, which may have cuased Xen to crash, resulting in a
 Denial
 of Service (DoS). (XSA-276) (bsc#1115043)

CVE-2018-19965: Fixed an issue related to the INVPCID instruction in
 case non-canonical addresses are accessed, which may allow a guest to
 cause Xen to crash, resulting in a Denial of Service (DoS) affecting the
 entire host. (XSA-279) (bsc#1115045)

CVE-2018-19966: Fixed an issue related to a previous fix for XSA-240,
 which conflicted with shadow paging and allowed a guest to cause Xen to
 crash, resulting in a Denial of Service (DoS) (XSA-280) (bsc#1115047)

CVE-2018-19967: Fixed HLE constructs that allowed guests to lock up the
 host, resulting in a Denial of Service (DoS). (XSA-282) (bsc#1114988)

CVE-2018-19964: Fixed the incorrect error handling of p2m page removals,
 which allowed a guest to cause a deadlock, resulting in a Denial of
 Service (DoS) affecting the entire host. (XSA-277) (bsc#1115044)

CVE-2018-19665: Fixed an integer overflow resulting in memory corruption
 in various Bluetooth functions, allowing this to crash qemu process
 resulting in Denial of Service (DoS). (bsc#1117756).

Other bugs fixed:
Fixed an issue related to a domU hang on SLE12-SP3 HV (bsc#1108940)");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.11.1_02~2.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.11.1_02~2.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.11.1_02~2.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.11.1_02~2.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.11.1_02~2.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.11.1_02~2.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.11.1_02~2.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.11.1_02~2.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.11.1_02~2.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.11.1_02~2.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.11.1_02~2.3.1", rls:"SLES12.0SP4"))) {
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
