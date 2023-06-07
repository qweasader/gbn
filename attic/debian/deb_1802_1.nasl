# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 1802-1 (squirrelmail)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2009 E-Soft Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.64033");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2009-05-25 20:59:33 +0200 (Mon, 25 May 2009)");
  script_cve_id("CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1580", "CVE-2009-1581");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 1802-1 (squirrelmail)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Debian Local Security Checks");
      script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201802-1");
  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in SquirrelMail,
a webmail application. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2009-1578

Cross site scripting was possible through a number of pages which
allowed an attacker to steal sensitive session data.

CVE-2009-1579

Code injection was possible when SquirrelMail was configured to
use the map_yp_alias function to authenticate users. This is not
the default.

CVE-2009-1580

It was possible to hijack an active user session by planting a
specially crafted cookie into the user's browser.

CVE-2009-1581

Specially crafted HTML emails could use the CSS positioning feature
to place email content over the SquirrelMail user interface, allowing
for phishing.

For the old stable distribution (etch), these problems have been fixed in
version 1.4.9a-4.

For the stable distribution (lenny), these problems have been fixed in
version 1.4.15-4+lenny1.

For the unstable distribution (sid), these problems have been fixed in
version 1.4.18-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your squirrelmail package.");
  script_tag(name:"summary", value:"The remote host is missing an update to squirrelmail announced via advisory DSA 1802-1. [This VT has been merged into the VT 'deb_1802.nasl' (OID: 1.3.6.1.4.1.25623.1.0.64033).]");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);