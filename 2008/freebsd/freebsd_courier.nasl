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
  script_oid("1.3.6.1.4.1.25623.1.0.52431");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0224");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: courier");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:
   courier
   courier-imap
   sqwebmail

CVE-2004-0224
Multiple buffer overflows in (1) iso2022jp.c or (2) shiftjis.c for
Courier-IMAP before 3.0.0, Courier before 0.45, and SqWebMail before
4.0.0 may allow remote attackers to execute arbitrary code 'when
Unicode character is out of BMP range.'");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://cvs.sourceforge.net/viewcvs.py/courier/libs/unicode/iso2022jp.c?rev=1.10&view=markup");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9845");
  script_xref(name:"URL", value:"http://cvs.sourceforge.net/viewcvs.py/courier/libs/unicode/shiftjis.c?rev=1.6&view=markup");
  script_xref(name:"URL", value:"http://secunia.com/advisories/11087");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/98bd69c3-834b-11d8-a41f-0020ed76ef5a.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

txt = "";
vuln = FALSE;

bver = portver(pkg:"courier");
if(!isnull(bver) && revcomp(a:bver, b:"0.45")<0) {
  txt += 'Package courier version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"courier-imap");
if(!isnull(bver) && revcomp(a:bver, b:"3.0,1")<0) {
  txt += 'Package courier-imap version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"sqwebmail");
if(!isnull(bver) && revcomp(a:bver, b:"4.0")<0) {
  txt += 'Package sqwebmail version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}