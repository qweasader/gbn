# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.70712");
  script_cve_id("CVE-2011-0216", "CVE-2011-2821", "CVE-2011-2834", "CVE-2011-3905", "CVE-2011-3919");
  script_tag(name:"creation_date", value:"2012-02-11 08:29:27 +0000 (Sat, 11 Feb 2012)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2394)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2394");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2394");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2394");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxml2' package(s) announced via the DSA-2394 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Many security problems have been fixed in libxml2, a popular library to handle XML data files.

CVE-2011-3919: Juri Aedla discovered a heap-based buffer overflow that allows remote attackers to cause a denial of service or possibly have unspecified other impact via unknown vectors.

CVE-2011-0216: An Off-by-one error have been discovered that allows remote attackers to execute arbitrary code or cause a denial of service.

CVE-2011-2821: A memory corruption (double free) bug has been identified in libxml2's XPath engine. Through it, it is possible for an attacker to cause a denial of service or possibly have unspecified other impact. This vulnerability does not affect the oldstable distribution (lenny).

CVE-2011-2834: Yang Dingning discovered a double free vulnerability related to XPath handling.

CVE-2011-3905: An out-of-bounds read vulnerability had been discovered, which allows remote attackers to cause a denial of service.

For the oldstable distribution (lenny), this problem has been fixed in version 2.6.32.dfsg-5+lenny5.

For the stable distribution (squeeze), this problem has been fixed in version 2.7.8.dfsg-2+squeeze2.

For the testing distribution (wheezy), this problem has been fixed in version 2.7.8.dfsg-7.

For the unstable distribution (sid), this problem has been fixed in version 2.7.8.dfsg-7.

We recommend that you upgrade your libxml2 packages.");

  script_tag(name:"affected", value:"'libxml2' package(s) on Debian 5, Debian 6.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-dbg", ver:"2.6.32.dfsg-5+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-dev", ver:"2.6.32.dfsg-5+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-doc", ver:"2.6.32.dfsg-5+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-utils", ver:"2.6.32.dfsg-5+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2", ver:"2.6.32.dfsg-5+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-libxml2", ver:"2.6.32.dfsg-5+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-dbg", ver:"2.7.8.dfsg-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-dev", ver:"2.7.8.dfsg-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-doc", ver:"2.7.8.dfsg-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-utils", ver:"2.7.8.dfsg-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2", ver:"2.7.8.dfsg-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-libxml2-dbg", ver:"2.7.8.dfsg-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-libxml2", ver:"2.7.8.dfsg-2+squeeze2", rls:"DEB6"))) {
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
