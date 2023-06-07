# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 502-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53192");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0399", "CVE-2004-0400");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 502-1 (exim-tls)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20502-1");
  script_tag(name:"insight", value:"Georgi Guninski discovered two stack-based buffer overflows in exim
and exim-tls.  They can not be exploited with the default
configuration from the Debian system, though.  The Common
Vulnerabilities and Exposures project identifies the following
problems that are fixed with this update:

CVE-2004-0399

When sender_verify = true is configured in exim.conf a buffer
overflow can happen during verification of the sender.  This
problem is fixed in exim 4.

CVE-2004-0400

When headers_check_syntax is configured in exim.conf a buffer
overflow can happen during the header check.  This problem does
also exist in exim 4.

For the stable distribution (woody) these problems have been fixed in
version 3.35-3woody2.

The unstable distribution (sid) does not contain exim-tls anymore.
The functionality has been incorporated in the main exim versions
which have these problems fixed in version 3.36-11 for exim 3 and in
version 4.33-1 for exim 4.");

  script_tag(name:"solution", value:"We recommend that you upgrade your exim-tls package.");
  script_tag(name:"summary", value:"The remote host is missing an update to exim-tls
announced via advisory DSA 502-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"exim-tls", ver:"3.35-3woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
