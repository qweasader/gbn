# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.66210");
  script_cve_id("CVE-2009-2372", "CVE-2009-2373", "CVE-2009-2374");
  script_tag(name:"creation_date", value:"2009-11-11 14:56:44 +0000 (Wed, 11 Nov 2009)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1930)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1930");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1930");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1930");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal6' package(s) announced via the DSA-1930 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in drupal6, a fully-featured content management framework. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-2372

Gerhard Killesreiter discovered a flaw in the way user signatures are handled. It is possible for a user to inject arbitrary code via a crafted user signature. (SA-CORE-2009-007)

CVE-2009-2373

Mark Piper, Sven Herrmann and Brandon Knight discovered a cross-site scripting issue in the forum module, which could be exploited via the tid parameter. (SA-CORE-2009-007)

CVE-2009-2374

Sumit Datta discovered that certain drupal6 pages leak sensitive information such as user credentials. (SA-CORE-2009-007)

Several design flaws in the OpenID module have been fixed, which could lead to cross-site request forgeries or privilege escalations. Also, the file upload function does not process all extensions properly leading to the possible execution of arbitrary code. (SA-CORE-2009-008)

The oldstable distribution (etch) does not contain drupal6.

For the stable distribution (lenny), these problems have been fixed in version 6.6-3lenny3.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 6.14-1.

We recommend that you upgrade your drupal6 packages.");

  script_tag(name:"affected", value:"'drupal6' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"drupal6", ver:"6.6-3lenny3", rls:"DEB5"))) {
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
