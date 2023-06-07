# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 159-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53417");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1119");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 159-1 (python)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20159-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5581");
  script_tag(name:"insight", value:"Zack Weinberg discovered an insecure use of a temporary file in
os._execvpe from os.py.  It uses a predictable name which could lead
execution of arbitrary code.

This problem has been fixed in several versions of Python: For the
current stable distribution (woody) it has been fixed in version
1.5.2-23.1 of Python 1.5, in version 2.1.3-3.1 of Python 2.1 and in
version 2.2.1-4.1 of Python 2.2.  For the old stable distribution
(potato) this has been fixed in version 1.5.2-10potato12 for Python
1.5.  For the unstable distribution (sid) this has been fixed in
version 1.5.2-24 of Python 1.5, in version 2.1.3-6a of Python 2.1 and
in version 2.2.1-8 of Python 2.2.  Python 2.3 is not affected by this
problem.");

  script_tag(name:"solution", value:"We recommend that you upgrade your Python packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to python announced via advisory DSA 159-1.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-159)' (OID: 1.3.6.1.4.1.25623.1.0.53730).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);