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
  script_oid("1.3.6.1.4.1.25623.1.0.60180");
  script_cve_id("CVE-2007-3278", "CVE-2007-4769", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-6600", "CVE-2007-6601");
  script_tag(name:"creation_date", value:"2008-01-31 15:11:48 +0000 (Thu, 31 Jan 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1463)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1463");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1463");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1463");
  script_xref(name:"URL", value:"http://www.postgresql.org/about/news.905");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql, postgresql-7.4' package(s) announced via the DSA-1463 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in PostgreSQL, an object-relational SQL database. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-3278

It was discovered that the DBLink module performed insufficient credential validation. This issue is also tracked as CVE-2007-6601, since the initial upstream fix was incomplete.

CVE-2007-4769

Tavis Ormandy and Will Drewry discovered that a bug in the handling of back-references inside the regular expressions engine could lead to an out of bounds read, resulting in a crash. This constitutes only a security problem if an application using PostgreSQL processes regular expressions from untrusted sources.

CVE-2007-4772

Tavis Ormandy and Will Drewry discovered that the optimizer for regular expression could be tricked into an infinite loop, resulting in denial of service. This constitutes only a security problem if an application using PostgreSQL processes regular expressions from untrusted sources.

CVE-2007-6067

Tavis Ormandy and Will Drewry discovered that the optimizer for regular expression could be tricked massive resource consumption. This constitutes only a security problem if an application using PostgreSQL processes regular expressions from untrusted sources.

CVE-2007-6600

Functions in index expressions could lead to privilege escalation. For a more in depth explanation please see the upstream announce available at [link moved to references].

For the old stable distribution (sarge), some of these problems have been fixed in version 7.4.7-6sarge6 of the postgresql package. Please note that the fix for CVE-2007-6600 and for the handling of regular expressions haven't been backported due to the intrusiveness of the fix. We recommend to upgrade to the stable distribution if these vulnerabilities affect your setup.

For the stable distribution (etch), these problems have been fixed in version 7.4.19-0etch1.

The unstable distribution (sid) no longer contains postgres-7.4.

We recommend that you upgrade your postgresql-7.4 packages.");

  script_tag(name:"affected", value:"'postgresql, postgresql-7.4' package(s) on Debian 3.1, Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-dev", ver:"7.4.7-6sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg4", ver:"7.4.7-6sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpgtcl-dev", ver:"7.4.7-6sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpgtcl", ver:"7.4.7-6sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq3", ver:"7.4.7-6sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client", ver:"7.4.7-6sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib", ver:"7.4.7-6sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-dev", ver:"7.4.7-6sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc", ver:"7.4.7-6sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql", ver:"7.4.7-6sarge6", rls:"DEB3.1"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-7.4", ver:"1:7.4.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-7.4", ver:"1:7.4.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib-7.4", ver:"1:7.4.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc-7.4", ver:"1:7.4.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plperl-7.4", ver:"1:7.4.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plpython-7.4", ver:"1:7.4.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-pltcl-7.4", ver:"1:7.4.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-server-dev-7.4", ver:"1:7.4.19-0etch1", rls:"DEB4"))) {
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
