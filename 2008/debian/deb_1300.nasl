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
  script_oid("1.3.6.1.4.1.25623.1.0.58351");
  script_cve_id("CVE-2007-1116", "CVE-2007-1362", "CVE-2007-1558", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2870", "CVE-2007-2871");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1300)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1300");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1300");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1300");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceape' package(s) announced via the DSA-1300 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Iceape internet suite, an unbranded version of the Seamonkey Internet Suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1362

Nicolas Derouet discovered that Iceape performs insufficient validation of cookies, which could lead to denial of service.

CVE-2007-1558

Gatan Leurent discovered a cryptographical weakness in APOP authentication, which reduces the required efforts for an MITM attack to intercept a password. The update enforces stricter validation, which prevents this attack.

CVE-2007-2867

Boris Zbarsky, Eli Friedman, Georgi Guninski, Jesse Ruderman, Martijn Wargers and Olli Pettay discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2007-2868

Brendan Eich, Igor Bukanov, Jesse Ruderman, moz_bug_r_a4 and Wladimir Palant discovered crashes in the javascript engine, which might allow the execution of arbitrary code.

CVE-2007-2870

moz_bug_r_a4 discovered that adding an event listener through the addEventListener() function allows cross-site scripting.

CVE-2007-2871

Chris Thomas discovered that XUL popups can be abused for spoofing or phishing attacks.

Fixes for the oldstable distribution (sarge) are not available. While there will be another round of security updates for Mozilla products, Debian doesn't have the resources to backport further security fixes to the old Mozilla products. You're strongly encouraged to upgrade to stable as soon as possible.

For the stable distribution (etch) these problems have been fixed in version 1.0.9-0etch1. A build for the arm architecture is not yet available, it will be provided later.

The unstable distribution (sid) will be fixed soon.

We recommend that you upgrade your iceape packages.");

  script_tag(name:"affected", value:"'iceape' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"iceape-browser", ver:"1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-calendar", ver:"1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-chatzilla", ver:"1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-dbg", ver:"1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-dev", ver:"1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-dom-inspector", ver:"1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-gnome-support", ver:"1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-mailnews", ver:"1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape", ver:"1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-browser", ver:"2:1.8+1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-calendar", ver:"2:1.8+1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-chatzilla", ver:"2:1.8+1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-dev", ver:"2:1.8+1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-dom-inspector", ver:"2:1.8+1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-js-debugger", ver:"2:1.8+1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-mailnews", ver:"2:1.8+1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-psm", ver:"2:1.8+1.0.9-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla", ver:"2:1.8+1.0.9-0etch1", rls:"DEB4"))) {
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
