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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2770.1");
  script_cve_id("CVE-2020-14374", "CVE-2020-14375", "CVE-2020-14376", "CVE-2020-14377", "CVE-2020-14378");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:53 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-04 16:15:00 +0000 (Mon, 04 Jan 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2770-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2770-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202770-1/");
  script_xref(name:"URL", value:"https://doc.dpdk.org/guides-19.11/rel_notes/release_19_11.html#id8");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dpdk' package(s) announced via the SUSE-SU-2020:2770-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dpdk fixes the following issues:

dpdk was updated to 19.11.4
 -
CVE-2020-14374,CVE-2020-14375,CVE-2020-14376,CVE-2020-14377,CVE-2020-14378:
 Fixed multiple issues where a malicious guest could harm the host
 using vhost crypto, including executing code in host (VM Escape),
 reading host application memory space to guest and causing partially
 denial of service in the host(bsc#1176590).

For a list of fixes check:
 [link moved to references]
 denial of service in the host (bsc#1176590).");

  script_tag(name:"affected", value:"'dpdk' package(s) on SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP2, SUSE Linux Enterprise Module for Server Applications 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libdpdk-20_0", rpm:"libdpdk-20_0~19.11.4~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdpdk-20_0-debuginfo", rpm:"libdpdk-20_0-debuginfo~19.11.4~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk", rpm:"dpdk~19.11.4~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-debuginfo", rpm:"dpdk-debuginfo~19.11.4~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-debugsource", rpm:"dpdk-debugsource~19.11.4~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-devel", rpm:"dpdk-devel~19.11.4~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-devel-debuginfo", rpm:"dpdk-devel-debuginfo~19.11.4~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-default", rpm:"dpdk-kmp-default~19.11.4_k5.3.18_24.15~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-default-debuginfo", rpm:"dpdk-kmp-default-debuginfo~19.11.4_k5.3.18_24.15~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx", rpm:"dpdk-thunderx~19.11.4~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-debuginfo", rpm:"dpdk-thunderx-debuginfo~19.11.4~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-debugsource", rpm:"dpdk-thunderx-debugsource~19.11.4~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-devel", rpm:"dpdk-thunderx-devel~19.11.4~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-devel-debuginfo", rpm:"dpdk-thunderx-devel-debuginfo~19.11.4~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-kmp-default", rpm:"dpdk-thunderx-kmp-default~19.11.4_k5.3.18_24.15~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-kmp-default-debuginfo", rpm:"dpdk-thunderx-kmp-default-debuginfo~19.11.4_k5.3.18_24.15~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-tools", rpm:"dpdk-tools~19.11.4~3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-tools-debuginfo", rpm:"dpdk-tools-debuginfo~19.11.4~3.9.1", rls:"SLES15.0SP2"))) {
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
