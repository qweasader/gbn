# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 2237-1 (apr)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2011 E-Soft Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.69734");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_cve_id("CVE-2011-0419");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 2237-1 (apr)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202237-1");
  script_tag(name:"insight", value:"A flaw was found in the APR library, which could be exploited through
Apache HTTPD's mod_autoindex.  If a directory indexed by mod_autoindex
contained files with sufficiently long names, a remote attacker could
send a carefully crafted request which would cause excessive CPU
usage. This could be used in a denial of service attack.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.2.12-5+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.2-6+squeeze1.

For the testing distribution (wheezy), this problem will be fixed in
version 1.4.4-1.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.4-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your apr packages and restart the");
  script_tag(name:"summary", value:"The remote host is missing an update to apr announced via advisory DSA 2237-1. [This VT has been merged into the VT 'deb_2237.nasl' (OID: 1.3.6.1.4.1.25623.1.0.69734).]");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
