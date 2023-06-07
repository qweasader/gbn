###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from vuxml or freebsd advisories
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52495");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0083", "CVE-2004-0084", "CVE-2004-0106");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: XFree86-Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: XFree86-Server

CVE-2004-0083
Buffer overflow in ReadFontAlias from dirfile.c of XFree86 4.1.0
through 4.3.0 allows local users and remote attackers to execute
arbitrary code via a font alias file (font.alias) with a long token, a
different vulnerability than CVE-2004-0084 and CVE-2004-0106.

CVE-2004-0084
Buffer overflow in the ReadFontAlias function in XFree86 4.1.0 to
4.3.0, when using the CopyISOLatin1Lowered function, allows local or
remote authenticated users to execute arbitrary code via a malformed
entry in the font alias (font.alias) file, a different vulnerability
than CVE-2004-0083 and CVE-2004-0106.

CVE-2004-0106
Multiple unknown vulnerabilities in XFree86 4.1.0 to 4.3.0, related to
improper handling of font files, a different set of vulnerabilities
than CVE-2004-0083 and CVE-2004-0084.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=72");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9636");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9652");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9655");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=73");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/3837f462-5d6b-11d8-80e3-0020ed76ef5a.html");

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

bver = portver(pkg:"XFree86-Server");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.0_13")<=0) {
  txt += 'Package XFree86-Server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"4.3.99")>=0 && revcomp(a:bver, b:"4.3.99.15_1")<=0) {
  txt += 'Package XFree86-Server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}