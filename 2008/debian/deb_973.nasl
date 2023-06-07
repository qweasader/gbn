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
  script_oid("1.3.6.1.4.1.25623.1.0.56281");
  script_cve_id("CVE-2005-3893", "CVE-2005-3894", "CVE-2005-3895");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-973)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-973");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-973");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-973");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'otrs' package(s) announced via the DSA-973 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in otrs, the Open Ticket Request System, that can be exploited remotely. The Common Vulnerabilities and Exposures Project identifies the following problems:

CVE-2005-3893

Multiple SQL injection vulnerabilities allow remote attackers to execute arbitrary SQL commands and bypass authentication.

CVE-2005-3894

Multiple cross-site scripting vulnerabilities allow remote authenticated users to inject arbitrary web script or HTML.

CVE-2005-3895

Internally attached text/html mails are rendered as HTML when the queue moderator attempts to download the attachment, which allows remote attackers to execute arbitrary web script or HTML.

The old stable distribution (woody) does not contain OTRS packages.

For the stable distribution (sarge) these problems have been fixed in version 1.3.2p01-6.

For the unstable distribution (sid) these problems have been fixed in version 2.0.4p01-1.

We recommend that you upgrade your otrs package.");

  script_tag(name:"affected", value:"'otrs' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"otrs-doc-de", ver:"1.3.2p01-6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"otrs-doc-en", ver:"1.3.2p01-6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"otrs", ver:"1.3.2p01-6", rls:"DEB3.1"))) {
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
