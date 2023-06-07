# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 804-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.55260");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 23:03:37 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-1920");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Debian Security Advisory DSA 804-1 (kdelibs)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_tag(name:"solution", value:"For the stable distribution (sarge) this problem has been fixed in
version 3.3.2-6.2.

For the unstable distribution (sid) these problems have been fixed in
version 3.4.1-1.

  We recommend that you upgrade your kate package.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20804-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14297");
  script_tag(name:"summary", value:"The remote host is missing an update to kdelibs announced via advisory DSA 804-1.  KDE developers have reported a vulnerability in the backup file handling of Kate and Kwrite.  The backup files are created with default permissions, even if the original file had more strict permissions set.  This could disclose information unintendedly.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-804)' (OID: 1.3.6.1.4.1.25623.1.0.55847).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);