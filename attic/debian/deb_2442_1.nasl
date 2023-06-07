# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 2442-1 (openarena)
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
  script_oid("1.3.6.1.4.1.25623.1.0.71245");
  script_cve_id("CVE-2010-5077");
  script_version("2023-01-25T10:11:07+0000");
  script_tag(name:"last_modification", value:"2023-01-25 10:11:07 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"creation_date", value:"2012-04-30 07:55:18 -0400 (Mon, 30 Apr 2012)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Debian Security Advisory DSA 2442-1 (openarena)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202442-1");
  script_tag(name:"insight", value:"It has been discovered that spoofed getstatus UDP requests are being
sent by attackers to servers for use with games derived from the
Quake 3 engine (such as openarena).  These servers respond with a
packet flood to the victim whose IP address was impersonated by the
attackers, causing a denial of service.

For the stable distribution (squeeze), this problem has been fixed in
version 0.8.5-5+squeeze2.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 0.8.5-6.");

  script_tag(name:"solution", value:"We recommend that you upgrade your openarena packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to openarena announced via advisory DSA 2442-1.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-2442)' (OID: 1.3.6.1.4.1.25623.1.0.71248).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);