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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2528.1");
  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2018-10981", "CVE-2018-10982", "CVE-2018-11806", "CVE-2018-12617", "CVE-2018-12891", "CVE-2018-12893", "CVE-2018-3639", "CVE-2018-3646", "CVE-2018-3665");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:38 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-10 17:15:00 +0000 (Thu, 10 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2528-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2528-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182528-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2018:2528-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:
These security issue were fixed:
- CVE-2018-3646: Systems with microprocessors utilizing speculative
 execution and address translations may have allowed unauthorized
 disclosure of information residing in the L1 data cache to an attacker
 with local user access with guest OS privilege via a terminal page fault
 and a side-channel analysis (bsc#1091107, bsc#1027519).
- CVE-2018-12617: An integer overflow that could cause a segmentation
 fault in qmp_guest_file_read() with g_malloc() in qemu-guest-agent was
 fixed (bsc#1098744)
- CVE-2018-3665: System software utilizing Lazy FP state restore technique
 on systems using Intel Core-based microprocessors may potentially allow
 a local process to infer data from another process through a
 speculative execution side channel. (bsc#1095242)
- CVE-2018-3639: Systems with microprocessors utilizing speculative
 execution and speculative execution of memory reads before the addresses
 of all prior memory writes are known may allow unauthorized disclosure
 of information to an attacker with local user access via a side-channel
 analysis, aka Speculative Store Bypass (SSB), Variant 4. (bsc#1092631)
- CVE-2017-5715: Systems with microprocessors utilizing speculative
 execution and indirect branch prediction may allow unauthorized
 disclosure
 of information to an attacker with local user access via a side-channel
 analysis. (bsc#1074562)
- CVE-2017-5753: Systems with microprocessors utilizing speculative
 execution and branch prediction may allow unauthorized disclosure of
 information to an attacker with local user access via a side-channel
 analysis. (bsc#1074562)
- CVE-2017-5754: Systems with microprocessors utilizing speculative
 execution and indirect branch prediction may allow unauthorized
 disclosure
 of information to an attacker with local user access via a side-channel
 analysis of the data cache. (bsc#1074562)
- CVE-2018-12891: Certain PV MMU operations may take a long time to
 process. For that reason Xen explicitly checks for the need to preempt
 the current vCPU at certain points. A few rarely taken code paths did
 bypass such checks. By suitably enforcing the conditions through its own
 page table contents, a malicious guest may cause such bypasses to be
 used for an unbounded number of iterations. A malicious or buggy PV
 guest may cause a Denial of Service (DoS) affecting the entire host.
 Specifically, it may prevent use of a physical CPU for an indeterminate
 period of time. (bsc#1097521)
- CVE-2018-12893: One of the fixes in XSA-260 added some safety checks to
 help prevent Xen livelocking with debug exceptions. Unfortunately, due
 to an oversight, at least one of these safety checks can be triggered by
 a guest. A malicious PV guest can crash Xen, leading to a Denial of
 Service. Only x86 PV guests can exploit the vulnerability. x86 HVM and
 PVH guests cannot exploit ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.2.5_21~45.25.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.2.5_21~45.25.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.2.5_21~45.25.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.5_21_3.0.101_0.47.106.43~45.25.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.5_21_3.0.101_0.47.106.43~45.25.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.2.5_21~45.25.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.2.5_21~45.25.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.2.5_21~45.25.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.2.5_21~45.25.1", rls:"SLES11.0SP3"))) {
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
