# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 2480-3 (request-tracker3.8)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
  script_oid("1.3.6.1.4.1.25623.1.0.71465");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("2023-01-25T10:11:07+0000");
  script_tag(name:"last_modification", value:"2023-01-25 10:11:07 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"creation_date", value:"2012-08-10 02:57:14 -0400 (Fri, 10 Aug 2012)");
  script_name("Debian Security Advisory DSA 2480-3 (request-tracker3.8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202480-3");
  script_tag(name:"insight", value:"The recent security updates for request-tracker3.8, DSA-2480-1 and
DSA-2480-2, contained another regression when running under mod_perl.

Please note that if you run request-tracker3.8 under the Apache web
server, you must stop and start Apache manually.  The restart
mechanism is not recommended, especially when using mod_perl.

For the stable distribution (squeeze), this problem has been fixed in
version 3.8.8-7+squeeze4.");

  script_tag(name:"solution", value:"We recommend that you upgrade your request-tracker3.8 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to request-tracker3.8 announced via advisory DSA 2480-3.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-2480)' (OID: 1.3.6.1.4.1.25623.1.0.72206).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);