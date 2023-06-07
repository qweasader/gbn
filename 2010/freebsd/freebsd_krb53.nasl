###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID 9ac0f9c4-492b-11df-83fb-0015587e2cc1
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
  script_oid("1.3.6.1.4.1.25623.1.0.67291");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2010-04-21 03:31:17 +0200 (Wed, 21 Apr 2010)");
  script_cve_id("CVE-2010-0283", "CVE-2010-0628");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("FreeBSD Ports: krb5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: krb5

CVE-2010-0283
The Key Distribution Center (KDC) in MIT Kerberos 5 (aka krb5) 1.7
before 1.7.2, and 1.8 alpha, allows remote attackers to cause a denial
of service (assertion failure and daemon crash) via an invalid (1)
AS-REQ or (2) TGS-REQ request.

CVE-2010-0628
The spnego_gss_accept_sec_context function in
lib/gssapi/spnego/spnego_mech.c in the SPNEGO GSS-API functionality in
MIT Kerberos 5 (aka krb5) 1.7 before 1.7.2 and 1.8 before 1.8.1 allows
remote attackers to cause a denial of service (assertion failure and
daemon crash) via an invalid packet that triggers incorrect
preparation of an error token.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2010-001.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38260");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38904");
  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2010-002.txt");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/9ac0f9c4-492b-11df-83fb-0015587e2cc1.html");

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

bver = portver(pkg:"krb5");
if(!isnull(bver) && revcomp(a:bver, b:"1.7")>=0 && revcomp(a:bver, b:"1.7_2")<=0) {
  txt += 'Package krb5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}