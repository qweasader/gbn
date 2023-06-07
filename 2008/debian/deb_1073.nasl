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
  script_oid("1.3.6.1.4.1.25623.1.0.56789");
  script_cve_id("CVE-2006-0903", "CVE-2006-1516", "CVE-2006-1517", "CVE-2006-1518");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1073)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1073");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1073");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1073");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-dfsg-4.1' package(s) announced via the DSA-1073 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in MySQL, a popular SQL database. The Common Vulnerabilities and Exposures Project identifies the following problems:

CVE-2006-0903

Improper handling of SQL queries containing the NULL character allows local users to bypass logging mechanisms.

CVE-2006-1516

Usernames without a trailing null byte allow remote attackers to read portions of memory.

CVE-2006-1517

A request with an incorrect packet length allows remote attackers to obtain sensitive information.

CVE-2006-1518

Specially crafted request packets with invalid length values allow the execution of arbitrary code.

The following vulnerability matrix shows which version of MySQL in which distribution has this problem fixed:



woody

sarge

sid

mysql

3.23.49-8.15

n/a

n/a

mysql-dfsg

n/a

4.0.24-10sarge2

n/a

mysql-dfsg-4.1

n/a

4.1.11a-4sarge3

n/a

mysql-dfsg-5.0

n/a

n/a

5.0.21-3

We recommend that you upgrade your mysql packages.");

  script_tag(name:"affected", value:"'mysql-dfsg-4.1' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient14-dev", ver:"4.1.11a-4sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient14", ver:"4.1.11a-4sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client-4.1", ver:"4.1.11a-4sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-common-4.1", ver:"4.1.11a-4sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-4.1", ver:"4.1.11a-4sarge3", rls:"DEB3.1"))) {
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
