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
  script_oid("1.3.6.1.4.1.25623.1.0.57400");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-0047");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: freeciv, freeciv-gtk, freeciv-gtk2, freeciv-nox11");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  freeciv
   freeciv-gtk
   freeciv-gtk2
   freeciv-nox11

CVE-2006-0047
packets.c in Freeciv 2.0 before 2.0.8 allows remote attackers to cause
a denial of service (server crash) via crafted packets with negative
compressed size values.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/19120/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16975");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/freecivdos-adv.txt");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/339fbbc1-4d23-11db-b48d-00508d6a62df.html");

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

bver = portver(pkg:"freeciv");
if(!isnull(bver) && revcomp(a:bver, b:"2.0.8")<0) {
  txt += 'Package freeciv version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"freeciv-gtk");
if(!isnull(bver) && revcomp(a:bver, b:"2.0.8")<0) {
  txt += 'Package freeciv-gtk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"freeciv-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"2.0.8")<0) {
  txt += 'Package freeciv-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"freeciv-nox11");
if(!isnull(bver) && revcomp(a:bver, b:"2.0.8")<0) {
  txt += 'Package freeciv-nox11 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}