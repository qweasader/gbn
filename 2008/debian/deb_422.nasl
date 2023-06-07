# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 422-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53679");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0977");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 422-1 (cvs)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20422-1");
  script_tag(name:"insight", value:"The account management of the CVS pserver (which is used to give remote
access to CVS repositories) uses a CVSROOT/passwd file in each
repository which contains the accounts and their authentication
information as well as the name of the local unix account to use when a
pserver account is used. Since CVS performed no checking on what unix
account was specified anyone who could modify the CVSROOT/passwd could
gain access to all local users on the CVS server, including root.

This has been fixed in upstream version 1.11.11 by preventing pserver
from running as root. For Debian this problem is solved in version
1.11.1p1debian-9 in two different ways:

  * pserver is no longer allowed to use root to access repositories

  * a new /etc/cvs-repouid is introduced which can be used by the system
administrator to override the unix account used to access a
repository.

Additionally, CVS pserver had a bug in parsing module requests which
could be used to create files and directories outside a repository.
This has been fixed upstream in version 1.11.11 and Debian version
1.11.1p1debian-9 .

Finally, the umask used for 'cvs init' and 'cvs-makerepos' has been
changed to prevent repositories from being created with group write
permissions.");
  script_tag(name:"summary", value:"The remote host is missing an update to cvs
announced via advisory DSA 422-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"cvs", ver:"1.11.1p1debian-9", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
