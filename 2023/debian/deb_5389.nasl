# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5389");
  script_cve_id("CVE-2023-23913", "CVE-2023-28120");
  script_tag(name:"creation_date", value:"2023-04-17 04:20:16 +0000 (Mon, 17 Apr 2023)");
  script_version("2023-04-17T10:19:34+0000");
  script_tag(name:"last_modification", value:"2023-04-17 10:19:34 +0000 (Mon, 17 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-5389)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5389");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5389");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5389");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/rails");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rails' package(s) announced via the DSA-5389 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in rails, the Ruby based server-side MVC web application framework, which could lead to XSS and DOM based cross-site scripting (CRS).

This update also fixes a regression introduced in previous update that may block certain access for applications using development environment.

For the stable distribution (bullseye), these problems have been fixed in version 2:6.0.3.7+dfsg-2+deb11u2.

We recommend that you upgrade your rails packages.

For the detailed security status of rails please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'rails' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"rails", ver:"2:6.0.3.7+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-actioncable", ver:"2:6.0.3.7+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-actionmailbox", ver:"2:6.0.3.7+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-actionmailer", ver:"2:6.0.3.7+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-actionpack", ver:"2:6.0.3.7+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-actiontext", ver:"2:6.0.3.7+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-actionview", ver:"2:6.0.3.7+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-activejob", ver:"2:6.0.3.7+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-activemodel", ver:"2:6.0.3.7+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-activerecord", ver:"2:6.0.3.7+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-activestorage", ver:"2:6.0.3.7+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-activesupport", ver:"2:6.0.3.7+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-rails", ver:"2:6.0.3.7+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-railties", ver:"2:6.0.3.7+dfsg-2+deb11u2", rls:"DEB11"))) {
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
