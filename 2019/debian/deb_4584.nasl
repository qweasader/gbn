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
  script_oid("1.3.6.1.4.1.25623.1.0.704584");
  script_cve_id("CVE-2018-11805", "CVE-2019-12420");
  script_tag(name:"creation_date", value:"2019-12-15 03:00:06 +0000 (Sun, 15 Dec 2019)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-13 19:15:00 +0000 (Mon, 13 Jan 2020)");

  script_name("Debian: Security Advisory (DSA-4584)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4584");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4584");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4584");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/spamassassin");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'spamassassin' package(s) announced via the DSA-4584 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in spamassassin, a Perl-based spam filter using text analysis.

CVE-2018-11805

Malicious rule or configuration files, possibly downloaded from an updates server, could execute arbitrary commands under multiple scenarios.

CVE-2019-12420

Specially crafted multipart messages can cause spamassassin to use excessive resources, resulting in a denial of service.

For the oldstable distribution (stretch), these problems have been fixed in version 3.4.2-1~deb9u2.

For the stable distribution (buster), these problems have been fixed in version 3.4.2-1+deb10u1.

We recommend that you upgrade your spamassassin packages.

For the detailed security status of spamassassin please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'spamassassin' package(s) on Debian 9, Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"sa-compile", ver:"3.4.2-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"spamassassin", ver:"3.4.2-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"spamc", ver:"3.4.2-1+deb10u1", rls:"DEB10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"sa-compile", ver:"3.4.2-1~deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"spamassassin", ver:"3.4.2-1~deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"spamc", ver:"3.4.2-1~deb9u2", rls:"DEB9"))) {
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