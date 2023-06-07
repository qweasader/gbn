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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0737.1");
  script_cve_id("CVE-2012-6708", "CVE-2015-9251", "CVE-2019-15845", "CVE-2019-16201", "CVE-2019-16254", "CVE-2019-16255", "CVE-2020-8130");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0737-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0737-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200737-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.5' package(s) announced via the SUSE-SU-2020:0737-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ruby2.5 toversion 2.5.7 fixes the following issues:

ruby 2.5 was updated to version 2.5.7 CVE-2020-8130: Fixed a command injection in intree copy of rake
 (bsc#1164804).

CVE-2019-16255: Fixed a code injection vulnerability of Shell#[] and
 Shell#test (bsc#1152990).

CVE-2019-16254: Fixed am HTTP response splitting in WEBrick
 (bsc#1152992).

CVE-2019-15845: Fixed a null injection vulnerability of File.fnmatch and
 File.fnmatch? (bsc#1152994).

CVE-2019-16201: Fixed a regular expression denial of service of WEBrick
 Digest access authentication (bsc#1152995).

CVE-2012-6708: Fixed an XSS in JQuery

CVE-2015-9251: Fixed an XSS in JQuery

Fixed unit tests (bsc#1140844)

Removed some unneeded test files (bsc#1162396).");

  script_tag(name:"affected", value:"'ruby2.5' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libruby2_5-2_5", rpm:"libruby2_5-2_5~2.5.7~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2_5-2_5-debuginfo", rpm:"libruby2_5-2_5-debuginfo~2.5.7~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5", rpm:"ruby2.5~2.5.7~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-debuginfo", rpm:"ruby2.5-debuginfo~2.5.7~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-debugsource", rpm:"ruby2.5-debugsource~2.5.7~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel", rpm:"ruby2.5-devel~2.5.7~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel-extra", rpm:"ruby2.5-devel-extra~2.5.7~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-stdlib", rpm:"ruby2.5-stdlib~2.5.7~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-stdlib-debuginfo", rpm:"ruby2.5-stdlib-debuginfo~2.5.7~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libruby2_5-2_5", rpm:"libruby2_5-2_5~2.5.7~4.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2_5-2_5-debuginfo", rpm:"libruby2_5-2_5-debuginfo~2.5.7~4.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5", rpm:"ruby2.5~2.5.7~4.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-debuginfo", rpm:"ruby2.5-debuginfo~2.5.7~4.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-debugsource", rpm:"ruby2.5-debugsource~2.5.7~4.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel", rpm:"ruby2.5-devel~2.5.7~4.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel-extra", rpm:"ruby2.5-devel-extra~2.5.7~4.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-stdlib", rpm:"ruby2.5-stdlib~2.5.7~4.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-stdlib-debuginfo", rpm:"ruby2.5-stdlib-debuginfo~2.5.7~4.8.1", rls:"SLES15.0"))) {
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
