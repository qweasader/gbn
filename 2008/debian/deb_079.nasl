# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 079-2
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
  script_oid("1.3.6.1.4.1.25623.1.0.53389");
  script_cve_id("CVE-2001-0873");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 079-2 (uucp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20079-2");
  script_tag(name:"insight", value:"Zenith Parsec discovered a security hole in Taylor UUCP 1.06.1.  It
permits a local user to copy any file to anywhere which is writable by
the uucp uid, which effectively means that a local user can completely
subvert the UUCP subsystem, including stealing mail, etc.

If a remote user with UUCP access is able to create files on the local
system, and can successfully make certain guesses about the local
directory structure layout, then the remote user can also subvert the
UUCP system.  A default installation of UUCP will permit a remote user
to create files on the local system if the UUCP public directory has
been created with world write permissions.

Obviously this security hole is serious for anybody who uses UUCP on a
multi-user system with untrusted users, or anybody who uses UUCP and
permits connections from untrusted remote systems.

It was thought that this problem has been fixed with DSA 079-1, but
that didn't fix all variations of the problem.  The problem is fixed
in version 1.06.1-11potato2 of uucp which uses a patch from the
upstream author Ian Lance Taylor.");

  script_tag(name:"solution", value:"We recommend that you upgrade your uucp packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to uucp
announced via advisory DSA 079-2.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"uucp", ver:"1.06.1-11potato2", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
