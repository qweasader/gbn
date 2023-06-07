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
  script_oid("1.3.6.1.4.1.25623.1.0.52399");
  script_version("2022-01-18T16:34:09+0000");
  script_tag(name:"last_modification", value:"2022-01-18 16:34:09 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0218", "CVE-2004-0219", "CVE-2004-0220", "CVE-2004-0221", "CVE-2004-0222");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: isakmpd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: isakmpd

CVE-2004-0218
isakmpd in OpenBSD 3.4 and earlier allows remote attackers to cause a
denial of service (infinite loop) via an ISAKMP packet with a
zero-length payload, as demonstrated by the Striker ISAKMP Protocol
Test Suite.

CVE-2004-0219
isakmpd in OpenBSD 3.4 and earlier allows remote attackers to cause a
denial of service (crash) via an ISAKMP packet with a malformed IPSEC
SA payload, as demonstrated by the Striker ISAKMP Protocol Test Suite.

CVE-2004-0220
isakmpd in OpenBSD 3.4 and earlier allows remote attackers to cause a
denial of service via an ISAKMP packet with a malformed Cert Request
payload, which causes an integer underflow that is used in a malloc
operation that is not properly handled, , as demonstrated by the
Striker ISAKMP Protocol Test Suite.

CVE-2004-0221
isakmpd in OpenBSD 3.4 and earlier allows remote attackers to cause a
denial of service (crash) via an ISAKMP packet with a delete payload
containing a large number of SPIs, which triggers an out-of-bounds
read error, as demonstrated by the Striker ISAKMP Protocol Test Suite.

CVE-2004-0222
Multiple memory leaks in isakmpd in OpenBSD 3.4 and earlier allow
remote attackers to cause a denial of service (memory exhaustion) via
certain ISAKMP packets, as demonstrated by the Striker ISAKMP Protocol
Test Suite.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.rapid7.com/advisories/R7-0018.html");
  script_xref(name:"URL", value:"http://www.openbsd.org/errata34.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/b7cb488c-8349-11d8-a41f-0020ed76ef5a.html");

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

bver = portver(pkg:"isakmpd");
if(!isnull(bver) && revcomp(a:bver, b:"20030903")<=0) {
  txt += 'Package isakmpd version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
