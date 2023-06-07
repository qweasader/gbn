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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1352.2");
  script_cve_id("CVE-2019-9947");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:22 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-08-18T10:11:39+0000");
  script_tag(name:"last_modification", value:"2022-08-18 10:11:39 +0000 (Thu, 18 Aug 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:00:00 +0000 (Tue, 16 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1352-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1352-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191352-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3' package(s) announced via the SUSE-SU-2019:1352-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python3 to version 3.6.8 fixes the following issues:

Security issue fixed:
CVE-2019-9947: Fixed an issue in urllib2 which allowed CRLF injection if
 the attacker controls a url parameter (bsc#1130840).

Non-security issue fixed:
Fixed broken debuginfo packages by switching off LTO and PGO
 optimization (bsc#1133452).");

  script_tag(name:"affected", value:"'python3' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_6m1_0", rpm:"libpython3_6m1_0~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_6m1_0-debuginfo", rpm:"libpython3_6m1_0-debuginfo~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base", rpm:"python3-base~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-debuginfo", rpm:"python3-base-debuginfo~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base-debugsource", rpm:"python3-base-debugsource~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-curses", rpm:"python3-curses~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-curses-debuginfo", rpm:"python3-curses-debuginfo~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-dbm", rpm:"python3-dbm~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-dbm-debuginfo", rpm:"python3-dbm-debuginfo~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debuginfo", rpm:"python3-debuginfo~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debugsource", rpm:"python3-debugsource~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-devel", rpm:"python3-devel~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-devel-debuginfo", rpm:"python3-devel-debuginfo~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-idle", rpm:"python3-idle~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tk", rpm:"python3-tk~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tk-debuginfo", rpm:"python3-tk-debuginfo~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tools", rpm:"python3-tools~3.6.8~3.16.2", rls:"SLES15.0SP1"))) {
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
