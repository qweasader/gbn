###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from vuxml or freebsd advisories
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2008 E-Soft Inc. http://www.securityspace.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.53075");
  script_version("2022-01-18T16:34:09+0000");
  script_tag(name:"last_modification", value:"2022-01-18 16:34:09 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-1267", "CVE-2005-1278", "CVE-2005-1279", "CVE-2005-1280");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: tcpdump");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: tcpdump

CVE-2005-1278
The isis_print function, as called by isoclns_print, in tcpdump 3.9.1
and earlier allows remote attackers to cause a denial of service
(infinite loop) via a zero length, as demonstrated using a GRE packet.

CVE-2005-1279
tcpdump 3.8.3 and earlier allows remote attackers to cause a denial of
service (infinite loop) via a crafted (1) BGP packet, which is not
properly handled by RT_ROUTING_INFO, or (2) LDP packet, which is not
properly handled by the ldp_print function.

CVE-2005-1280
The rsvp_print function in tcpdump 3.9.1 and earlier allows remote
attackers to cause a denial of service (infinite loop) via a crafted
RSVP packet of length 4.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=111454406222040");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=111454461300644");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=111928309502304");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/9fae0f1f-df82-11d9-b875-0001020eed82.html");

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

bver = portver(pkg:"tcpdump");
if(!isnull(bver) && revcomp(a:bver, b:"3.8.3_2")<0) {
  txt += 'Package tcpdump version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}