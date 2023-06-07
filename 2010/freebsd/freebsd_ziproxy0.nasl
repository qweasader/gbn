###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID b43004b8-6a53-11df-bc7b-0245fb008c0b
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2010 E-Soft Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.67408");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2010-06-03 22:55:24 +0200 (Thu, 03 Jun 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1513");
  script_name("FreeBSD Ports: ziproxy");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: ziproxy

CVE-2010-1513
Multiple integer overflows in src/image.c in Ziproxy before 3.0.1
allow remote attackers to execute arbitrary code via (1) a large JPG
image, related to the jpg2bitmap function or (2) a large PNG image,
related to the png2bitmap function, leading to heap-based buffer
overflows.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://ziproxy.sourceforge.net/#news");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40344");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39941");
  script_xref(name:"URL", value:"http://sourceforge.net/mailarchive/message.php?msg_name=201005210019.37119.dancab%40gmx.net");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/b43004b8-6a53-11df-bc7b-0245fb008c0b.html");

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

bver = portver(pkg:"ziproxy");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.1")<0) {
  txt += 'Package ziproxy version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}