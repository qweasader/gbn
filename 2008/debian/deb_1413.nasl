# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.59638");
  script_cve_id("CVE-2007-2583", "CVE-2007-2691", "CVE-2007-2692", "CVE-2007-3780", "CVE-2007-3782", "CVE-2007-5925");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1413)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1413");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1413");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1413");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-dfsg, mysql-dfsg-4.1, mysql-dfsg-5.0' package(s) announced via the DSA-1413 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the MySQL database packages with implications ranging from unauthorized database modifications to remotely triggered server crashes. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2583

The in_decimal::set function in item_cmpfunc.cc in MySQL before 5.0.40 allows context-dependent attackers to cause a denial of service (crash) via a crafted IF clause that results in a divide-by-zero error and a NULL pointer dereference. (Affects source version 5.0.32.)

CVE-2007-2691

MySQL does not require the DROP privilege for RENAME TABLE statements, which allows remote authenticated users to rename arbitrary tables. (All supported versions affected.)

CVE-2007-2692

The mysql_change_db function does not restore THD::db_access privileges when returning from SQL SECURITY INVOKER stored routines, which allows remote authenticated users to gain privileges. (Affects source version 5.0.32.)

CVE-2007-3780

MySQL could be made to overflow a signed char during authentication. Remote attackers could use specially crafted authentication requests to cause a denial of service. (Upstream source versions 4.1.11a and 5.0.32 affected.)

CVE-2007-3782

Phil Anderton discovered that MySQL did not properly verify access privileges when accessing external tables. As a result, authenticated users could exploit this to obtain UPDATE privileges to external tables. (Affects source version 5.0.32.)

CVE-2007-5925

The convert_search_mode_to_innobase function in ha_innodb.cc in the InnoDB engine in MySQL 5.1.23-BK and earlier allows remote authenticated users to cause a denial of service (database crash) via a certain CONTAINS operation on an indexed column, which triggers an assertion error. (Affects source version 5.0.32.)

For the old stable distribution (sarge), these problems have been fixed in version 4.0.24-10sarge3 of mysql-dfsg and version 4.1.11a-4sarge8 of mysql-dfsg-4.1.

For the stable distribution (etch), these problems have been fixed in version 5.0.32-7etch3 of the mysql-dfsg-5.0 packages.

We recommend that you upgrade your mysql packages.");

  script_tag(name:"affected", value:"'mysql-dfsg, mysql-dfsg-4.1, mysql-dfsg-5.0' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient12-dev", ver:"4.0.24-10sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient12", ver:"4.0.24-10sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient14-dev", ver:"4.1.11a-4sarge8", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient14", ver:"4.1.11a-4sarge8", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client-4.1", ver:"4.1.11a-4sarge8", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client", ver:"4.0.24-10sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-common-4.1", ver:"4.1.11a-4sarge8", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-common", ver:"4.0.24-10sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-4.1", ver:"4.1.11a-4sarge8", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server", ver:"4.0.24-10sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.32-7etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.32-7etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client-5.0", ver:"5.0.32-7etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.32-7etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.32-7etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-4.1", ver:"5.0.32-7etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.32-7etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.32-7etch3", rls:"DEB4"))) {
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
