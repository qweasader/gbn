# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.705039");
  script_cve_id("CVE-2022-21661", "CVE-2022-21662", "CVE-2022-21663", "CVE-2022-21664");
  script_tag(name:"creation_date", value:"2022-01-11 13:38:48 +0000 (Tue, 11 Jan 2022)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-14 12:40:00 +0000 (Fri, 14 Jan 2022)");

  script_name("Debian: Security Advisory (DSA-5039)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"Advisory-ID", value:"DSA-5039");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5039");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5039");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wordpress");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-5039 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Wordpress, a web blogging tool. They allowed remote attackers to perform SQL injection, run unchecked SQL queries, bypass hardening, or perform Cross-Site Scripting (XSS) attacks.

For the oldstable distribution (buster), these problems have been fixed in version 5.0.15+dfsg1-0+deb10u1.

For the stable distribution (bullseye), these problems have been fixed in version 5.7.5+dfsg1-0+deb11u1.

We recommend that you upgrade your wordpress packages.

For the detailed security status of wordpress please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 10, Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"5.0.15+dfsg1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentynineteen", ver:"5.0.15+dfsg1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyseventeen", ver:"5.0.15+dfsg1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentysixteen", ver:"5.0.15+dfsg1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"5.0.15+dfsg1-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"5.7.5+dfsg1-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentynineteen", ver:"5.7.5+dfsg1-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentytwenty", ver:"5.7.5+dfsg1-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentytwentyone", ver:"5.7.5+dfsg1-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"5.7.5+dfsg1-0+deb11u1", rls:"DEB11"))) {
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
