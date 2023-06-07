###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID bce1f76d-82d0-11de-88ea-001a4d49522b
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
  script_oid("1.3.6.1.4.1.25623.1.0.64659");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2009-2411");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("FreeBSD Ports: subversion, subversion-freebsd, p5-subversion, py-subversion");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  subversion
   subversion-freebsd
   p5-subversion
   py-subversion

CVE-2009-2411
Multiple integer overflows in the libsvn_delta library in Subversion
before 1.5.7, and 1.6.x before 1.6.4, allow remote authenticated users
and remote Subversion servers to execute arbitrary code via an svndiff
stream with large windows that trigger a heap-based buffer overflow, a
related issue to CVE-2009-2412.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://subversion.tigris.org/security/CVE-2009-2411-advisory.txt");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/bce1f76d-82d0-11de-88ea-001a4d49522b.html");

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

bver = portver(pkg:"subversion");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4")<0) {
  txt += 'Package subversion version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"subversion-freebsd");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4")<0) {
  txt += 'Package subversion-freebsd version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"p5-subversion");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4")<0) {
  txt += 'Package p5-subversion version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py-subversion");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4")<0) {
  txt += 'Package py-subversion version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}