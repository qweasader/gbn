# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 662-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53494");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:56:38 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-0104", "CVE-2005-0152");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 662-1 (squirrelmail)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20662-1");
  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Squirrelmail, a
commonly used webmail system.  The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2005-0104

Upstream developers noticed that an unsanitised variable could
lead to cross site scripting.

CVE-2005-0152

Grant Hollingworth discovered that under certain circumstances URL
manipulation could lead to the execution of arbitrary code with
the privileges of www-data.  This problem only exists in version
1.2.6 of Squirrelmail.

For the stable distribution (woody) these problems have been fixed in
version 1.2.6-2.

For the unstable distribution (sid) the problem that affects unstable
has been fixed in version 1.4.4-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your squirrelmail package.");
  script_tag(name:"summary", value:"The remote host is missing an update to squirrelmail announced via advisory DSA 662-1.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-662)' (OID: 1.3.6.1.4.1.25623.1.0.53523).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);