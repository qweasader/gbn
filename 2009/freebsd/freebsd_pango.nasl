###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID 4b172278-3f46-11de-becb-001cc0377035
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
  script_oid("1.3.6.1.4.1.25623.1.0.64010");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2009-05-20 00:17:15 +0200 (Wed, 20 May 2009)");
  script_cve_id("CVE-2009-1194");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: pango, linux-pango, linux-f8-pango");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  pango
   linux-pango
   linux-f8-pango

CVE-2009-1194
Integer overflow in the pango_glyph_string_set_size function in
pango/glyphstring.c in Pango before 1.24 allows context-dependent
attackers to cause a denial of service (application crash) or possibly
execute arbitrary code via a long glyph string that triggers a
heap-based buffer overflow, as demonstrated by a long
document.location value in Firefox.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35021/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34870");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/4b172278-3f46-11de-becb-001cc0377035.html");

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

bver = portver(pkg:"pango");
if(!isnull(bver) && revcomp(a:bver, b:"1.24")<0) {
  txt += 'Package pango version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-pango");
if(!isnull(bver) && revcomp(a:bver, b:"1.24")<0) {
  txt += 'Package linux-pango version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-f8-pango");
if(!isnull(bver) && revcomp(a:bver, b:"1.24")<0) {
  txt += 'Package linux-f8-pango version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}