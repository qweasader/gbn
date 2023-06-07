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
  script_oid("1.3.6.1.4.1.25623.1.0.54424");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-1006");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("isc-dhcpd -- format string vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  isc-dhcp3-client, isc-dhcp3-devel, isc-dhcp3-relay, isc-dhcp3-server, isc-dhcp3
  isc-dhcp, isc-dhcpd

CVE-2004-1006
Format string vulnerability in the log functions in dhcpd for dhcp 2.x
allows remote DNS servers to execute arbitrary code via certain DNS
messages, a different vulnerability than CVE-2002-0702.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://marc.info/?l=dhcp-announce&m=109996073218290");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11591");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/ccd325d2-fa08-11d9-bc08-0001020eed82.html");

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

bver = portver(pkg:"isc-dhcp3-client");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.1")<0) {
  txt += 'Package isc-dhcp3-client version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"isc-dhcp3-devel");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.1")<0) {
  txt += 'Package isc-dhcp3-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"isc-dhcp3-relay");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.1")<0) {
  txt += 'Package isc-dhcp3-relay version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"isc-dhcp3-server");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.1")<0) {
  txt += 'Package isc-dhcp3-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"isc-dhcp3");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.1")<0) {
  txt += 'Package isc-dhcp3 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"isc-dhcp");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.1")<0) {
  txt += 'Package isc-dhcp version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"isc-dhcpd");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.1")<0) {
  txt += 'Package isc-dhcpd version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}