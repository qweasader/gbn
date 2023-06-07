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
  script_oid("1.3.6.1.4.1.25623.1.0.53650");
  script_cve_id("CVE-2003-0370", "CVE-2003-0459");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-361)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-361");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-361");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-361");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kdelibs, kdelibs-crypto' package(s) announced via the DSA-361 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in kdelibs:

CAN-2003-0459: KDE Konqueror for KDE 3.1.2 and earlier does not remove authentication credentials from URLs of the 'user:password@host' form in the HTTP-Referer header, which could allow remote web sites to steal the credentials for pages that link to the sites.

CAN-2003-0370: Konqueror Embedded and KDE 2.2.2 and earlier does not validate the Common Name (CN) field for X.509 Certificates, which could allow remote attackers to spoof certificates via a man-in-the-middle attack.

These vulnerabilities are described in the following security advisories from KDE:


For the current stable distribution (woody) these problems have been fixed in version 2.2.2-13.woody.8 of kdelibs and 2.2.2-6woody2 of kdelibs-crypto.

For the unstable distribution (sid) these problems have been fixed in kdelibs version 4:3.1.3-1. The unstable distribution does not contain a separate kdelibs-crypto package.

We recommend that you update your kdelibs and kdelibs-crypto packages.");

  script_tag(name:"affected", value:"'kdelibs, kdelibs-crypto' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs3-crypto", ver:"4:2.2.2-6woody2", rls:"DEB3.0"))) {
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
