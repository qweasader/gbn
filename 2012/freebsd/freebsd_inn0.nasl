###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID a7975581-ee26-11e1-8bd8-0022156e8794
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71837");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2012-3523", "CVE-2011-0411");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2012-08-30 11:34:18 -0400 (Thu, 30 Aug 2012)");
  script_name("FreeBSD Ports: inn");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: inn

CVE-2011-0411
The STARTTLS implementation in Postfix 2.4.x before 2.4.16, 2.5.x
before 2.5.12, 2.6.x before 2.6.9, and 2.7.x before 2.7.3 does not
properly restrict I/O buffering, which allows man-in-the-middle
attackers to insert commands into encrypted SMTP sessions by sending a
cleartext command that is processed after TLS is in place, related to
a 'plaintext command injection' attack.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://www.isc.org/software/inn/2.5.3article");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/a7975581-ee26-11e1-8bd8-0022156e8794.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"inn");
if(!isnull(bver) && revcomp(a:bver, b:"2.5.2_2")<0) {
  txt += "Package inn version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}