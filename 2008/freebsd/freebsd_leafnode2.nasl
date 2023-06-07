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
  script_oid("1.3.6.1.4.1.25623.1.0.52700");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-1453");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: leafnode");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: leafnode

CVE-2005-1453
fetchnews in leafnode 1.9.48 to 1.11.1 allows remote NNTP servers to
cause a denial of service (crash) by closing the connection while
fetchnews is reading (1) an article header or (2) an article body,
which also prevents fetchnews from querying other servers.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://leafnode.sourceforge.net/leafnode-SA-2005-01.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13489");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13492");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2005/0468");
  script_xref(name:"URL", value:"http://secunia.com/advisories/15252");
  script_xref(name:"URL", value:"http://sourceforge.net/mailarchive/forum.php?thread_id=7186974&forum_id=10210");
  script_xref(name:"URL", value:"http://article.gmane.org/gmane.network.leafnode.announce/52");
  script_xref(name:"URL", value:"http://www.dt.e-technik.uni-dortmund.de/pipermail/leafnode-list/2005q2/000900.html");
  script_xref(name:"URL", value:"http://www.fredi.de/maillist/msg00111.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/vulnwatch/2005-q2/0037.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/66dbb2ee-99b8-45b2-bb3e-640caea67a60.html");

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

bver = portver(pkg:"leafnode");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.48")>=0 && revcomp(a:bver, b:"1.11.2")<0) {
  txt += 'Package leafnode version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}