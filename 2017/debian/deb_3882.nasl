# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.703882");
  script_cve_id("CVE-2016-6127", "CVE-2017-5361", "CVE-2017-5943", "CVE-2017-5944");
  script_tag(name:"creation_date", value:"2017-06-14 22:00:00 +0000 (Wed, 14 Jun 2017)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-3882)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-3882");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3882");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3882");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'request-tracker4' package(s) announced via the DSA-3882 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Request Tracker, an extensible trouble-ticket tracking system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2016-6127

It was discovered that Request Tracker is vulnerable to a cross-site scripting (XSS) attack if an attacker uploads a malicious file with a certain content type. Installations which use the AlwaysDownloadAttachments config setting are unaffected by this flaw. The applied fix addresses all existent and future uploaded attachments.

CVE-2017-5361

It was discovered that Request Tracker is vulnerable to timing side-channel attacks for user passwords.

CVE-2017-5943

It was discovered that Request Tracker is prone to an information leak of cross-site request forgery (CSRF) verification tokens if a user is tricked into visiting a specially crafted URL by an attacker.

CVE-2017-5944

It was discovered that Request Tracker is prone to a remote code execution vulnerability in the dashboard subscription interface. A privileged attacker can take advantage of this flaw through carefully-crafted saved search names to cause unexpected code to be executed. The applied fix addresses all existent and future saved searches.

Additionally to the above mentioned CVEs, this update workarounds CVE-2015-7686 in Email::Address which could induce a denial of service of Request Tracker itself.

For the stable distribution (jessie), these problems have been fixed in version 4.2.8-3+deb8u2.

For the upcoming stable distribution (stretch), these problems have been fixed in version 4.4.1-3+deb9u1.

For the unstable distribution (sid), these problems have been fixed in version 4.4.1-4.

We recommend that you upgrade your request-tracker4 packages.");

  script_tag(name:"affected", value:"'request-tracker4' package(s) on Debian 8, Debian 9.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker4", ver:"4.2.8-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-apache2", ver:"4.2.8-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-clients", ver:"4.2.8-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-mysql", ver:"4.2.8-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-postgresql", ver:"4.2.8-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-sqlite", ver:"4.2.8-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-doc-html", ver:"4.2.8-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-fcgi", ver:"4.2.8-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-standalone", ver:"4.2.8-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker4", ver:"4.4.1-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-apache2", ver:"4.4.1-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-clients", ver:"4.4.1-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-mysql", ver:"4.4.1-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-postgresql", ver:"4.4.1-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-sqlite", ver:"4.4.1-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-doc-html", ver:"4.4.1-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-fcgi", ver:"4.4.1-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-standalone", ver:"4.4.1-3+deb9u1", rls:"DEB9"))) {
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
