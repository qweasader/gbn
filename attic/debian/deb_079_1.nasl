# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 079-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53570");
  script_cve_id("CVE-2001-0873");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 079-1 (uucp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20079-1");
  script_tag(name:"insight", value:"zen-parse has found a problem with Taylor UUCP as distributed with
many GNU/Linux distributions.  It was possible to make `uux' execute
`uucp' with malicious commandline arguments which gives an attacker
access to files owned by uid/gid uucp.

This problem has been fixed in version of 1.06.1-11potato1 for Debian
GNU/Linux 2.2 by using a patch that RedHat has provided.");

  script_tag(name:"solution", value:"We recommend that you upgrade your uucp package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to uucp announced via advisory DSA 079-1.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-079)' (OID: 1.3.6.1.4.1.25623.1.0.53389).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);