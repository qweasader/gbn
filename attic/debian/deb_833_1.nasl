# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 833-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.55514");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 23:03:37 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-2558");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 833-1 (mysql-dfsg-4.1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20833-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14509");
  script_tag(name:"insight", value:"A stack-based buffer overflow in the init_syms function of MySQL, a
popular database, has been discovered that allows remote authenticated
users who can create user-defined functions to execute arbitrary code
via a long function_name field.  The ability to create user-defined
functions is not typically granted to untrusted users.

The following vulnerability matrix explains which version of MySQL in
which distribution has this problem fixed:

                     woody              sarge              sid
mysql             3.23.49-8.14           n/a               n/a
mysql-dfsg            n/a          4.0.24-10sarge1    4.0.24-10sarge1
mysql-dfsg-4.1        n/a          4.1.11a-4sarge2        4.1.14-2
mysql-dfsg-5.0        n/a                n/a            5.0.11beta-3");

  script_tag(name:"solution", value:"We recommend that you upgrade your mysql-dfsg-4.1 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to mysql-dfsg-4.1 announced via advisory DSA 833-1.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-833)' (OID: 1.3.6.1.4.1.25623.1.0.55520).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);