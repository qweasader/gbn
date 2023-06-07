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
  script_oid("1.3.6.1.4.1.25623.1.0.57485");
  script_cve_id("CVE-2006-2788", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4568", "CVE-2006-4570", "CVE-2006-4571");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1191)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1191");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1191");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1191");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mozilla-thunderbird' package(s) announced via the DSA-1191 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in Mozilla and derived products such as Mozilla Thunderbird. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2006-2788

Fernando Ribeiro discovered that a vulnerability in the getRawDER function allows remote attackers to cause a denial of service (hang) and possibly execute arbitrary code.

CVE-2006-4340

Daniel Bleichenbacher recently described an implementation error in RSA signature verification that cause the application to incorrectly trust SSL certificates.

CVE-2006-4565, CVE-2006-4566 Priit Laes reported that a JavaScript regular expression can trigger a heap-based buffer overflow which allows remote attackers to cause a denial of service and possibly execute arbitrary code.

CVE-2006-4568

A vulnerability has been discovered that allows remote attackers to bypass the security model and inject content into the sub-frame of another site.

CVE-2006-4570

Georgi Guninski demonstrated that even with JavaScript disabled in mail (the default) an attacker can still execute JavaScript when a mail message is viewed, replied to, or forwarded.

CVE-2006-4571

Multiple unspecified vulnerabilities in Firefox, Thunderbird and SeaMonkey allow remote attackers to cause a denial of service, corrupt memory, and possibly execute arbitrary code.

For the stable distribution (sarge) these problems have been fixed in version 1.0.2-2.sarge1.0.8c.1.

For the unstable distribution (sid) these problems have been fixed in version 1.5.0.7-1.

We recommend that you upgrade your Mozilla Thunderbird packages.");

  script_tag(name:"affected", value:"'mozilla-thunderbird' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.0.2-2.sarge1.0.8c.1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.0.2-2.sarge1.0.8c.1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-offline", ver:"1.0.2-2.sarge1.0.8c.1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.0.2-2.sarge1.0.8c.1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.0.2-2.sarge1.0.8c.1", rls:"DEB3.1"))) {
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
