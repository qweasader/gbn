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
  script_oid("1.3.6.1.4.1.25623.1.0.55874");
  script_cve_id("CVE-2005-3325");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-893)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.0|3\.1)");

  script_xref(name:"Advisory-ID", value:"DSA-893");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-893");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-893");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'acidlab' package(s) announced via the DSA-893 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Remco Verhoef has discovered a vulnerability in acidlab, Analysis Console for Intrusion Databases, and in acidbase, Basic Analysis and Security Engine, which can be exploited by malicious users to conduct SQL injection attacks.

The maintainers of Analysis Console for Intrusion Databases (ACID) in Debian, of which BASE is a fork off, after a security audit of both BASE and ACID have determined that the flaw found not only affected the base_qry_main.php (in BASE) or acid_qry_main.php (in ACID) component but was also found in other elements of the consoles due to improper parameter validation and filtering.

All the SQL injection bugs and Cross Site Scripting bugs found have been fixed in the Debian package, closing all the different attack vectors detected.

For the old stable distribution (woody) this problem has been fixed in version 0.9.6b20-2.1.

For the stable distribution (sarge) this problem has been fixed in version 0.9.6b20-10.1.

For the unstable distribution (sid) this problem has been fixed in version 0.9.6b20-13 and in version 1.2.1-1 of acidbase.

We recommend that you upgrade your acidlab and acidbase package.");

  script_tag(name:"affected", value:"'acidlab' package(s) on Debian 3.0, Debian 3.1.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"acidlab", ver:"0.9.6b20-2.1", rls:"DEB3.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"acidlab-doc", ver:"0.9.6b20-10.1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acidlab-mysql", ver:"0.9.6b20-10.1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acidlab-pgsql", ver:"0.9.6b20-10.1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acidlab", ver:"0.9.6b20-10.1", rls:"DEB3.1"))) {
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
