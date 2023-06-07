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
  script_oid("1.3.6.1.4.1.25623.1.0.52501");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2003-0993");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: apache");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  apache, apache+mod_ssl, apache+ssl, ru-apache, ru-apache+mod_ssl

CVE-2003-0993
mod_access in Apache 1.3 before 1.3.30, when running big-endian 64-bit
platforms, does not properly parse Allow/Deny rules using IP addresses
without a netmask, which could allow remote attackers to bypass
intended access restrictions.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://cvs.apache.org/viewcvs.cgi/apache-1.3/src/modules/standard/mod_access.c?r1=1.46&r2=1.47");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9829");
  script_xref(name:"URL", value:"http://www.apacheweek.com/features/security-13");
  script_xref(name:"URL", value:"http://nagoya.apache.org/bugzilla/show_bug.cgi?id=23850");
  script_xref(name:"URL", value:"https://marc.info/?l=apache-cvs&m=107869603013722");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/09d418db-70fd-11d8-873f-0020ed76ef5a.html");

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

bver = portver(pkg:"apache");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.29_2")<0) {
  txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.29+2.8.16_1")<0) {
  txt += 'Package apache+mod_ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.29.1.53_1")<0) {
  txt += 'Package apache+ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ru-apache");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.29+30.19_1")<0) {
  txt += 'Package ru-apache version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ru-apache+mod_ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.29+30.19+2.8.16_1")<0) {
  txt += 'Package ru-apache+mod_ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}