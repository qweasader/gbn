# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 1569-1 (cacti)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.60935");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-05-12 19:53:28 +0200 (Mon, 12 May 2008)");
  script_cve_id("CVE-2008-0783", "CVE-2008-0785");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 1569-1 (cacti)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201569-1");
  script_tag(name:"insight", value:"It was discovered that Cacti, a systems and services monitoring frontend,
performed insufficient input sanitising, leading to cross site scripting
and SQL injection being possible.

For the stable distribution (etch), this problem has been fixed in
version 0.8.6i-3.3.

For the unstable distribution (sid), this problem has been fixed in
version 0.8.7b-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your cacti package.");
  script_tag(name:"summary", value:"The remote host is missing an update to cacti announced via advisory DSA 1569-1.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-1569)' (OID: 1.3.6.1.4.1.25623.1.0.60936).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);