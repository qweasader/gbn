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
  script_oid("1.3.6.1.4.1.25623.1.0.123736");
  script_cve_id("CVE-2012-5659", "CVE-2012-5660");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:52 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T08:27:53+0000");
  script_tag(name:"last_modification", value:"2022-04-05 08:27:53 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0215)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0215");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0215.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'abrt, libreport' package(s) announced via the ELSA-2013-0215 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"abrt
[2.0.8-6.0.1.el6_3.2]
- Add abrt-oracle-enterprise.patch to be product neutral
- Remove abrt-plugin-rhtsupport dependency for cli and desktop
- Make abrt Obsoletes/Provides abrt-plugin-rhtsupprot

[2.0.8-6.2]
- rebuild against new libreport (brew bug)
- Related: #895442

[2.0.8-6.1]
- don't follow symlinks
- Related: #895442

libreport
[2.0.9-5.0.1.el6_3.2]
- Add oracle-enterprise.patch
- Remove libreport-plugin-rhtsupport pkg

[2.0.9-5.2]
- in same cases we have to follow symlinks
- Related: #895442

[2.0.9-5.1]
- don't follow symlinks
- Resolves: #895442");

  script_tag(name:"affected", value:"'abrt, libreport' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"abrt", rpm:"abrt~2.0.8~6.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-ccpp", rpm:"abrt-addon-ccpp~2.0.8~6.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-kerneloops", rpm:"abrt-addon-kerneloops~2.0.8~6.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-python", rpm:"abrt-addon-python~2.0.8~6.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-vmcore", rpm:"abrt-addon-vmcore~2.0.8~6.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-cli", rpm:"abrt-cli~2.0.8~6.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-desktop", rpm:"abrt-desktop~2.0.8~6.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-devel", rpm:"abrt-devel~2.0.8~6.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-gui", rpm:"abrt-gui~2.0.8~6.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-libs", rpm:"abrt-libs~2.0.8~6.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-tui", rpm:"abrt-tui~2.0.8~6.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport", rpm:"libreport~2.0.9~5.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-cli", rpm:"libreport-cli~2.0.9~5.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-devel", rpm:"libreport-devel~2.0.9~5.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-gtk", rpm:"libreport-gtk~2.0.9~5.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-gtk-devel", rpm:"libreport-gtk-devel~2.0.9~5.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-newt", rpm:"libreport-newt~2.0.9~5.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-bugzilla", rpm:"libreport-plugin-bugzilla~2.0.9~5.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-kerneloops", rpm:"libreport-plugin-kerneloops~2.0.9~5.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-logger", rpm:"libreport-plugin-logger~2.0.9~5.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-mailx", rpm:"libreport-plugin-mailx~2.0.9~5.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-reportuploader", rpm:"libreport-plugin-reportuploader~2.0.9~5.0.1.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-python", rpm:"libreport-python~2.0.9~5.0.1.el6_3.2", rls:"OracleLinux6"))) {
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
