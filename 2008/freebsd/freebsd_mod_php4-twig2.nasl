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
  script_oid("1.3.6.1.4.1.25623.1.0.52371");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0595");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("php -- strip_tags cross-site scripting vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  mod_php4-twig, php4, php4-cgi, php4-cli, php4-dtc, php4-horde, php4-nms,
  mod_php4, php5, php5-cgi, php5-cli, mod_php5

CVE-2004-0595
The strip_tags function in PHP 4.x up to 4.3.7, and 5.x up to
5.0.0RC3, does not filter null (\0) characters within tag names when
restricting input to allowed tags, which allows dangerous tags to be
processed by web browsers such as Internet Explorer and Safari, which
ignore null characters and facilitate the exploitation of cross-site
scripting (XSS) vulnerabilities.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://security.e-matters.de/advisories/122004.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10724");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=108981589117423");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/edf61c61-0f07-11d9-8393-000103ccf9d6.html");

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

bver = portver(pkg:"mod_php4-twig");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.7_3")<=0) {
  txt += 'Package mod_php4-twig version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.7_3")<=0) {
  txt += 'Package php4 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4-cgi");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.7_3")<=0) {
  txt += 'Package php4-cgi version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4-cli");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.7_3")<=0) {
  txt += 'Package php4-cli version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4-dtc");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.7_3")<=0) {
  txt += 'Package php4-dtc version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4-horde");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.7_3")<=0) {
  txt += 'Package php4-horde version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4-nms");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.7_3")<=0) {
  txt += 'Package php4-nms version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mod_php4");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.7_3,1")<=0) {
  txt += 'Package mod_php4 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php5");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.0.r3_2")<=0) {
  txt += 'Package php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php5-cgi");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.0.r3_2")<=0) {
  txt += 'Package php5-cgi version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php5-cli");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.0.r3_2")<=0) {
  txt += 'Package php5-cli version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mod_php5");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.0.r3_2,1")<=0) {
  txt += 'Package mod_php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}