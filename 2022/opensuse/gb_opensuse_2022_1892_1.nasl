# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854718");
  script_version("2023-10-19T05:05:21+0000");
  script_cve_id("CVE-2021-3839", "CVE-2022-0669");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-26 19:24:00 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-06-01 01:01:36 +0000 (Wed, 01 Jun 2022)");
  script_name("openSUSE: Security Advisory for dpdk (SUSE-SU-2022:1892-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1892-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/H7KOPKHWXCWISP2YYJXIEUMWGDCOIDMZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dpdk'
  package(s) announced via the SUSE-SU-2022:1892-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dpdk fixes the following issues:
  Security:

  - CVE-2021-3839: Fixed a memory corruption issue during vhost-user
       communication (bsc#1198963).

  - CVE-2022-0669: Fixed a denial of service that could be triggered by a
       vhost-user master (bsc#1198964).
  Bugfixes:

  - kni: allow configuring thread granularity (bsc#1195172).

  - Fixed reading of PCI device name as UTF strings (bsc#1198873).");

  script_tag(name:"affected", value:"'dpdk' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-preempt", rpm:"dpdk-kmp-preempt~19.11.4_k5.3.18_150300.59.63~150300.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-preempt-debuginfo", rpm:"dpdk-kmp-preempt-debuginfo~19.11.4_k5.3.18_150300.59.63~150300.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-kmp-preempt", rpm:"dpdk-thunderx-kmp-preempt~19.11.4_k5.3.18_150300.59.63~150300.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-kmp-preempt-debuginfo", rpm:"dpdk-thunderx-kmp-preempt-debuginfo~19.11.4_k5.3.18_150300.59.63~150300.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"dpdk", rpm:"dpdk~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-debuginfo", rpm:"dpdk-debuginfo~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-debugsource", rpm:"dpdk-debugsource~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-devel", rpm:"dpdk-devel~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-devel-debuginfo", rpm:"dpdk-devel-debuginfo~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-examples", rpm:"dpdk-examples~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-examples-debuginfo", rpm:"dpdk-examples-debuginfo~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-default", rpm:"dpdk-kmp-default~19.11.4_k5.3.18_150300.59.63~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-default-debuginfo", rpm:"dpdk-kmp-default-debuginfo~19.11.4_k5.3.18_150300.59.63~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-tools", rpm:"dpdk-tools~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-tools-debuginfo", rpm:"dpdk-tools-debuginfo~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdpdk-20_0", rpm:"libdpdk-20_0~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdpdk-20_0-debuginfo", rpm:"libdpdk-20_0-debuginfo~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-preempt", rpm:"dpdk-kmp-preempt~19.11.4_k5.3.18_150300.59.63~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-preempt-debuginfo", rpm:"dpdk-kmp-preempt-debuginfo~19.11.4_k5.3.18_150300.59.63~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx", rpm:"dpdk-thunderx~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-debuginfo", rpm:"dpdk-thunderx-debuginfo~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-debugsource", rpm:"dpdk-thunderx-debugsource~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-devel", rpm:"dpdk-thunderx-devel~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-devel-debuginfo", rpm:"dpdk-thunderx-devel-debuginfo~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-examples", rpm:"dpdk-thunderx-examples~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-examples-debuginfo", rpm:"dpdk-thunderx-examples-debuginfo~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-kmp-default", rpm:"dpdk-thunderx-kmp-default~19.11.4_k5.3.18_150300.59.63~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-kmp-default-debuginfo", rpm:"dpdk-thunderx-kmp-default-debuginfo~19.11.4_k5.3.18_150300.59.63~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-kmp-preempt", rpm:"dpdk-thunderx-kmp-preempt~19.11.4_k5.3.18_150300.59.63~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-kmp-preempt-debuginfo", rpm:"dpdk-thunderx-kmp-preempt-debuginfo~19.11.4_k5.3.18_150300.59.63~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-tools", rpm:"dpdk-thunderx-tools~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-tools-debuginfo", rpm:"dpdk-thunderx-tools-debuginfo~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-doc", rpm:"dpdk-doc~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-doc", rpm:"dpdk-thunderx-doc~19.11.4~150300.11.1", rls:"openSUSELeap15.3"))) {
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