# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 811-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.55345");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 23:03:37 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-2657");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 811-1 (common-lisp-controller)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_tag(name:"solution", value:"For the stable distribution (sarge) this problem has been fixed in
version 4.15sarge2.

For the unstable distribution (sid) this problem has been fixed in
version 4.18.

  We recommend that you upgrade your common-lisp-controller package.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20811-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14829");
  script_tag(name:"summary", value:"The remote host is missing an update to common-lisp-controller announced via advisory DSA 811-1.  Francois-Rene Rideau discovered a bug in common-lisp-controller, a Common Lisp source and compiler manager, that allows a local user to compile malicious code into a cache directory which is executed by another user if that user has not used Common Lisp before.  The old stable distribution (woody) is not affected by this problem.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-811)' (OID: 1.3.6.1.4.1.25623.1.0.55898).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);