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
  script_oid("1.3.6.1.4.1.25623.1.0.52434");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0633", "CVE-2004-0634", "CVE-2004-0635");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: ethereal, ethereal-lite, tethereal, tethereal-lite");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:
   ethereal
   ethereal-lite
   tethereal
   tethereal-lite

CVE-2004-0633
The iSNS dissector for Ethereal 0.10.3 through 0.10.4 allows remote
attackers to cause a denial of service (process abort) via an integer
overflow.

CVE-2004-0634
The SMB SID snooping capability in Ethereal 0.9.15 to 0.10.4 allows
remote attackers to cause a denial of service (process crash) via a
handle without a policy name, which causes a null dereference.

CVE-2004-0635
The SNMP dissector in Ethereal 0.8.15 through 0.10.4 allows remote
attackers to cause a denial of service (process crash) via a (1)
malformed or (2) missing community string, which causes an
out-of-bounds read.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.ethereal.com/appnotes/enpa-sa-00015.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10672");
  script_xref(name:"URL", value:"http://secunia.com/advisories/12024");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/265c8b00-d2d0-11d8-b479-02e0185c0b53.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

txt = "";
vuln = FALSE;

bver = portver(pkg:"ethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.10.5")<0) {
  txt += 'Package ethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.10.5")<0) {
  txt += 'Package ethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.10.5")<0) {
  txt += 'Package tethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.10.5")<0) {
  txt += 'Package tethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}