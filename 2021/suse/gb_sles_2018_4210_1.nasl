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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.4210.1");
  script_cve_id("CVE-2018-15518", "CVE-2018-19873");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-14T02:23:29+0000");
  script_tag(name:"last_modification", value:"2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 09:15:00 +0000 (Mon, 28 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:4210-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:4210-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20184210-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt5-qtbase' package(s) announced via the SUSE-SU-2018:4210-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt5-qtbase fixes the following issues:

Security issues fixed:
CVE-2018-15518: Fixed double free in QXmlStreamReader (bsc#1118595)

CVE-2018-19873: Fixed Denial of Service on malformed BMP file in
 QBmpHandler (bsc#1118596)");

  script_tag(name:"affected", value:"'libqt5-qtbase' package(s) on SUSE Linux Enterprise Server 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libQt5Core5", rpm:"libQt5Core5~5.5.1~8.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Core5-debuginfo", rpm:"libQt5Core5-debuginfo~5.5.1~8.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5DBus5", rpm:"libQt5DBus5~5.5.1~8.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5DBus5-debuginfo", rpm:"libQt5DBus5-debuginfo~5.5.1~8.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Gui5", rpm:"libQt5Gui5~5.5.1~8.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Gui5-debuginfo", rpm:"libQt5Gui5-debuginfo~5.5.1~8.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Network5", rpm:"libQt5Network5~5.5.1~8.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Network5-debuginfo", rpm:"libQt5Network5-debuginfo~5.5.1~8.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Widgets5", rpm:"libQt5Widgets5~5.5.1~8.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Widgets5-debuginfo", rpm:"libQt5Widgets5-debuginfo~5.5.1~8.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-debugsource", rpm:"libqt5-qtbase-debugsource~5.5.1~8.3.1", rls:"SLES12.0SP1"))) {
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