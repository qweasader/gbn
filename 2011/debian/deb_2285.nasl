# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.70059");
  script_cve_id("CVE-2011-2703", "CVE-2011-2704");
  script_tag(name:"creation_date", value:"2011-08-07 15:37:07 +0000 (Sun, 07 Aug 2011)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2285)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2285");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2285");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2285");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mapserver' package(s) announced via the DSA-2285 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in mapserver, a CGI-based web framework to publish spatial data and interactive mapping applications. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2011-2703

Several instances of insufficient escaping of user input, leading to SQL injection attacks via OGC filter encoding (in WMS, WFS, and SOS filters).

CVE-2011-2704

Missing length checks in the processing of OGC filter encoding that can lead to stack-based buffer overflows and the execution of arbitrary code.

For the oldstable distribution (lenny), these problems have been fixed in version 5.0.3-3+lenny7.

For the stable distribution (squeeze), these problems have been fixed in version 5.6.5-2+squeeze2.

For the testing (squeeze) and unstable (sid) distributions, these problems will be fixed soon.

We recommend that you upgrade your mapserver packages.");

  script_tag(name:"affected", value:"'mapserver' package(s) on Debian 5, Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cgi-mapserver", ver:"5.0.3-3+lenny7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmapscript-ruby1.8", ver:"5.0.3-3+lenny7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmapscript-ruby1.9", ver:"5.0.3-3+lenny7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmapscript-ruby", ver:"5.0.3-3+lenny7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mapserver-bin", ver:"5.0.3-3+lenny7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mapserver-doc", ver:"5.0.3-3+lenny7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-mapscript", ver:"5.0.3-3+lenny7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-mapscript", ver:"5.0.3-3+lenny7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-mapscript", ver:"5.0.3-3+lenny7", rls:"DEB5"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cgi-mapserver", ver:"5.6.5-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmapscript-ruby1.8", ver:"5.6.5-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmapscript-ruby1.9.1", ver:"5.6.5-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmapscript-ruby", ver:"5.6.5-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mapserver-bin", ver:"5.6.5-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mapserver-doc", ver:"5.6.5-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-mapscript", ver:"5.6.5-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-mapscript", ver:"5.6.5-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-mapscript", ver:"5.6.5-2+squeeze2", rls:"DEB6"))) {
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
