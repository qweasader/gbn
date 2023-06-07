###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID eb9212f7-526b-11de-bbf2-001b77d09812
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
  script_oid("1.3.6.1.4.1.25623.1.0.64191");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2009-06-09 19:38:29 +0200 (Tue, 09 Jun 2009)");
  script_cve_id("CVE-2009-1955", "CVE-2009-1956", "CVE-2009-0023");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_name("FreeBSD Ports: apr");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  apr, apache

CVE-2009-1955
The expat XML parser in the apr_xml_* interface in xml/apr_xml.c in
Apache APR-util before 1.3.7, as used in the mod_dav and mod_dav_svn
modules in the Apache HTTP Server, allows remote attackers to cause a
denial of service (memory consumption) via a crafted XML document
containing a large number of nested entity references, as demonstrated
by a PROPFIND request, a similar issue to CVE-2003-1564.

CVE-2009-1956
Off-by-one error in the apr_brigade_vprintf function in Apache
APR-util before 1.3.5 on big-endian platforms allows remote attackers
to obtain sensitive information or cause a denial of service
(application crash) via crafted input.

CVE-2009-0023
The apr_strmatch_precompile function in strmatch/apr_strmatch.c in
Apache APR-util before 1.3.5 allows remote attackers to cause a denial
of service (daemon crash) via crafted input involving (1) a .htaccess
file used with the Apache HTTP Server, (2) the SVNMasterURI directive
in the mod_dav_svn module in the Apache HTTP Server, (3) the
mod_apreq2 module for the Apache HTTP Server, or (4) an application
that uses the libapreq2 library, related to an 'underflow flaw.'");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.apache.org/dist/apr/CHANGES-APR-UTIL-1.3");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35221");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35284/");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=3D504390");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/eb9212f7-526b-11de-bbf2-001b77d09812.html");

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

bver = portver(pkg:"apr");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.5.1.3.7")<0) {
  txt += 'Package apr version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.0")>=0 && revcomp(a:bver, b:"2.2.11_5")<0) {
  txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0.0")>=0 && revcomp(a:bver, b:"2.0.63_3")<0) {
  txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}