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
  script_oid("1.3.6.1.4.1.25623.1.0.56520");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-1550");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: dia, dia-gnome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  dia
   dia-gnome

CVE-2006-1550
Multiple buffer overflows in the xfig import code (xfig-import.c) in
Dia 0.87 and later before 0.95-pre6 allow user-complicit attackers to
have an unknown impact via a crafted xfig file, possibly involving an
invalid (1) color index, (2) number of points, or (3) depth.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/19469/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17310");
  script_xref(name:"URL", value:"http://mail.gnome.org/archives/dia-list/2006-March/msg00149.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/b5fc63ad-c4c3-11da-9699-00123ffe8333.html");

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

bver = portver(pkg:"dia");
if(!isnull(bver) && revcomp(a:bver, b:"0.86_1")>0 && revcomp(a:bver, b:"0.94_6,1")<0) {
  txt += 'Package dia version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"dia-gnome");
if(!isnull(bver) && revcomp(a:bver, b:"0.86_1")>0 && revcomp(a:bver, b:"0.94_6,1")<0) {
  txt += 'Package dia-gnome version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}