###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID 45298931-b3bf-11dd-80f8-001cc0377035
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
  script_oid("1.3.6.1.4.1.25623.1.0.61872");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-11-19 16:52:57 +0100 (Wed, 19 Nov 2008)");
  script_cve_id("CVE-2008-4989");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("FreeBSD Ports: gnutls");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: gnutls

CVE-2008-4989
The _gnutls_x509_verify_certificate function in lib/x509/verify.c in
libgnutls in GnuTLS before 2.6.1 trusts certificate chains in which
the last certificate is an arbitrary trusted, self-signed certificate,
which allows man-in-the-middle attackers to insert a spoofed
certificate for any Distinguished Name (DN).");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.gnu.org/software/gnutls/security.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32232");
  script_xref(name:"URL", value:"http://lists.gnu.org/archive/html/gnutls-devel/2008-11/msg00017.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/45298931-b3bf-11dd-80f8-001cc0377035.html");

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

bver = portver(pkg:"gnutls");
if(!isnull(bver) && revcomp(a:bver, b:"2.4.2")<0) {
  txt += 'Package gnutls version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}