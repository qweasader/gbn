# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 596-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53284");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-1051");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 596-1 (sudo)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20596-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11668");
  script_tag(name:"insight", value:"Liam Helmer noticed that sudo, a program that provides limited super
user privileges to specific users, does not clean the environment
sufficiently.  Bash functions and the CDPATH variable are still passed
through to the program running as privileged user, leaving
possibilities to overload system routines.  These vulnerabilities can
only be exploited by users who have been granted limited super user
privileges.

For the stable distribution (woody) these problems have been fixed in
version 1.6.6-1.2.

For the unstable distribution (sid) these problems have been fixed in
version 1.6.8p3.");

  script_tag(name:"solution", value:"We recommend that you upgrade your sudo package.");
  script_tag(name:"summary", value:"The remote host is missing an update to sudo announced via advisory DSA 596-1.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-596)' (OID: 1.3.6.1.4.1.25623.1.0.53283).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);