# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 081-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2008 E-Soft Inc.
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53759");
  script_cve_id("CVE-2001-0700");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 081-1 (w3m, w3m-ssl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20081-1");
  script_tag(name:"insight", value:"In SNS Advisory No. 32 a buffer overflow vulnerability has been
reported in the routine which parses MIME headers that are returned
from web servers.  A malicious web server administrator could exploit
this and let the client web browser execute arbitrary code.

W3m handles MIME headers included in the request/response message of
HTTP communication like any other we bbrowser.  A buffer overflow will
be occur when w3m receives a MIME encoded header with base64 format.

This problem has been fixed by the maintainer in version
0.1.10+0.1.11pre+kokb23-4 of w3m and w3m-ssl (for the SSL-enabled
version), both for Debian GNU/Linux 2.2.");

  script_tag(name:"solution", value:"We recommend that you upgrade your w3m packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to w3m, w3m-ssl
announced via advisory DSA 081-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"w3m", ver:"0.1.10+0.1.11pre+kokb23-4", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"w3m-ssl", ver:"0.1.10+0.1.11pre+kokb23-4", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
