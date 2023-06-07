# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 661-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53493");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:56:38 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-0017", "CVE-2005-0018");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Debian Security Advisory DSA 661-1 (f2c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20661-1");
  script_tag(name:"insight", value:"Javier Fernandez-Sanguino Pena from the Debian Security Audit project
discovered that f2c and fc, which are both part of the f2c package, a
fortran 77 to C/C++ translator, open temporary files insecurely and
are hence vulnerable to a symlink attack.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:

CVE-2005-0017

Multiple insecure temporary files in the f2c translator.

CVE-2005-0018

Two insecure temporary files in the f2 shell script.

For the stable distribution (woody) these problems have been fixed in
version 20010821-3.1

For the unstable distribution (sid) these problems will be fixed soon.");

  script_tag(name:"solution", value:"We recommend that you upgrade your f2c package.");
  script_tag(name:"summary", value:"The remote host is missing an update to f2c announced via advisory DSA 661-1.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-661)' (OID: 1.3.6.1.4.1.25623.1.0.53539).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);