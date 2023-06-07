# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 1270-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.58323");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 23:17:11 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2007-0002", "CVE-2007-0238", "CVE-2007-0239");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 1270-1 (openoffice.org)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_tag(name:"solution", value:"For the stable distribution (sarge) these problems have been fixed in
version 1.1.3-9sarge6.

For the testing distribution (etch) these problems have been fixed in
version 2.0.4.dfsg.2-6.

For the unstable distribution (sid) these problems have been fixed in
version 2.0.4.dfsg.2-6.

  We recommend that you upgrade your OpenOffice.org packages.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201270-1");
  script_tag(name:"summary", value:"The remote host is missing an update to openoffice.org announced via advisory DSA 1270-1.  Several security related problems have been discovered in OpenOffice.org, the free office suite.  The Common Vulnerabilities and Exposures project identifies the following problems:  CVE-2007-0002  iDefense reported several integer overflow bugs in libwpd, a library for handling WordPerfect documents that is included in OpenOffice.org.  Attackers are able to exploit these with carefully crafted WordPerfect files that could cause an application linked with libwpd to crash or possibly execute arbitrary code.  CVE-2007-0238  Next Generation Security discovered that the StarCalc parser in OpenOffice.org contains an easily exploitable stack overflow that could be used exploited by a specially crafted document to execute arbitrary code.  CVE-2007-0239  It has been reported that OpenOffice.org does not escape shell meta characters and is hence vulnerable to execute arbitrary shell commands via a specially crafted document after the user clicked to a prepared link.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-1270)' (OID: 1.3.6.1.4.1.25623.1.0.58326).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);