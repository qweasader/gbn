# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 1494-1 (linux-2.6)
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
  script_oid("1.3.6.1.4.1.25623.1.0.60369");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-02-15 23:29:21 +0100 (Fri, 15 Feb 2008)");
  script_cve_id("CVE-2008-0010", "CVE-2008-0163", "CVE-2008-0600");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 1494-1 (linux-2.6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201494-1");
  script_tag(name:"insight", value:"The vmsplice system call did not properly verify address arguments
passed by user space processes, which allowed local attackers to
overwrite arbitrary kernel memory, gaining root privileges
(CVE-2008-0010, CVE-2008-0600).

In the vserver-enabled kernels, a missing access check on certain
symlinks in /proc enabled local attackers to access resources in other
vservers (CVE-2008-0163).

For the stable distribution (etch), this problem has been fixed in version
2.6.18.dfsg.1-18etch1.

In addition to these fixes, this update also incorporates changes from the
upcoming point release of the stable distribution.

The old stable distribution (sarge) is not affected by this problem.

The unstable (sid) and testing distributions will be fixed soon.");

  script_tag(name:"solution", value:"We recommend that you upgrade your linux-2.6 package.");
  script_tag(name:"summary", value:"The remote host is missing an update to linux-2.6 announced via advisory DSA 1494-1.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-1494)' (OID: 1.3.6.1.4.1.25623.1.0.60372).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);