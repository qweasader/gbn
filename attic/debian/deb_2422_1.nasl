# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 2422-1 (file)
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
  script_oid("1.3.6.1.4.1.25623.1.0.71150");
  script_cve_id("CVE-2012-1571");
  script_version("2023-01-25T10:11:07+0000");
  script_tag(name:"last_modification", value:"2023-01-25 10:11:07 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"creation_date", value:"2012-03-12 11:33:02 -0400 (Mon, 12 Mar 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 2422-1 (file)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202422-1");
  script_tag(name:"insight", value:"The file type identification tool, file, and its associated library,
libmagic, do not properly process malformed files in the Composite
Document File (CDF) format, leading to crashes.

Note that after this update, file may return different detection
results for CDF files (well-formed or not).  The new detections are
believed to be more accurate.

For the stable distribution (squeeze), this problem has been fixed in
version 5.04-5+squeeze1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your file packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to file announced via advisory DSA 2422-1.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-2422)' (OID: 1.3.6.1.4.1.25623.1.0.71347).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);