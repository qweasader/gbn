# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852272");
  script_version("2023-02-02T10:09:00+0000");
  script_cve_id("CVE-2018-0734", "CVE-2019-2455", "CVE-2019-2481", "CVE-2019-2482", "CVE-2019-2503", "CVE-2019-2507", "CVE-2019-2529", "CVE-2019-2531", "CVE-2019-2534", "CVE-2019-2537");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-02-02 10:09:00 +0000 (Thu, 02 Feb 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-31 17:40:00 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"creation_date", value:"2019-02-06 04:05:05 +0100 (Wed, 06 Feb 2019)");
  script_name("openSUSE: Security Advisory for mysql-community-server (openSUSE-SU-2019:0138-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"openSUSE-SU", value:"2019:0138-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00005.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-community-server'
  package(s) announced via the openSUSE-SU-2019:0138-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mysql-community-server to version 5.6.43 fixes the
  following issues:

  Security issues fixed:

  - CVE-2019-2534, CVE-2019-2529, CVE-2019-2482, CVE-2019-2455,
  CVE-2019-2503, CVE-2019-2537, CVE-2019-2481, CVE-2019-2507,
  CVE-2019-2531, CVE-2018-0734  (boo#1113652, boo#1122198)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-138=1");

  script_tag(name:"affected", value:"mysql-community-server on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18", rpm:"libmysql56client18~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18-debuginfo", rpm:"libmysql56client18-debuginfo~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client_r18", rpm:"libmysql56client_r18~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server", rpm:"mysql-community-server~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-bench", rpm:"mysql-community-server-bench~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-bench-debuginfo", rpm:"mysql-community-server-bench-debuginfo~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-client", rpm:"mysql-community-server-client~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-client-debuginfo", rpm:"mysql-community-server-client-debuginfo~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-debuginfo", rpm:"mysql-community-server-debuginfo~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-debugsource", rpm:"mysql-community-server-debugsource~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-test", rpm:"mysql-community-server-test~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-test-debuginfo", rpm:"mysql-community-server-test-debuginfo~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-tools", rpm:"mysql-community-server-tools~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-tools-debuginfo", rpm:"mysql-community-server-tools-debuginfo~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18-32bit", rpm:"libmysql56client18-32bit~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18-debuginfo-32bit", rpm:"libmysql56client18-debuginfo-32bit~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client_r18-32bit", rpm:"libmysql56client_r18-32bit~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-errormessages", rpm:"mysql-community-server-errormessages~5.6.43~45.1", rls:"openSUSELeap42.3"))) {
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
