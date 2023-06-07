###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID 3b7967f1-49e8-11df-83fb-0015587e2cc1
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
  script_oid("1.3.6.1.4.1.25623.1.0.67289");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2010-04-21 03:31:17 +0200 (Wed, 21 Apr 2010)");
  script_cve_id("CVE-2010-1155", "CVE-2010-1156");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: irssi");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  irssi
   zh-irssi
   irssi-devel

CVE-2010-1155
Irssi before 0.8.15, when SSL is used, does not verify that the server
hostname matches a domain name in the subject's Common Name (CN) field
or a Subject Alternative Name field of the X.509 certificate, which
allows man-in-the-middle attackers to spoof IRC servers via an
arbitrary certificate.

CVE-2010-1156
core/nicklist.c in Irssi before 0.8.15 allows remote attackers to
cause a denial of service (NULL pointer dereference and application
crash) via vectors related to an attempted fuzzy nick match at the
instant that a victim leaves a channel.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57790");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57791");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/3b7967f1-49e8-11df-83fb-0015587e2cc1.html");

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

bver = portver(pkg:"irssi");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.15")<0) {
  txt += 'Package irssi version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zh-irssi");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.15")<0) {
  txt += 'Package zh-irssi version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"irssi-devel");
if(!isnull(bver) && revcomp(a:bver, b:"20100325")<0) {
  txt += 'Package irssi-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}