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
  script_oid("1.3.6.1.4.1.25623.1.0.52370");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0902");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  thunderbird
   firefox
   mozilla
   mozilla-gtk1
   linux-mozilla
   linux-mozillafirebird

CVE-2004-0902
Multiple heap-based buffer overflows in Mozilla Firefox before the
Preview Release, Mozilla before 1.7.3, and Thunderbird before 0.8
allow remote attackers to cause a denial of service (application
crash) or execute arbitrary code via (1) the 'Send page'
functionality, (2) certain responses from a malicious POP3 server, or
(3) a link containing a non-ASCII hostname.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://bugzilla.mozilla.org/show_bug.cgi?id=258005");
  script_xref(name:"URL", value:"http://bugzilla.mozilla.org/show_bug.cgi?id=245066");
  script_xref(name:"URL", value:"http://bugzilla.mozilla.org/show_bug.cgi?id=226669");
  script_xref(name:"URL", value:"http://bugzilla.mozilla.org/show_bug.cgi?id=256316");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/93d6162f-1153-11d9-bc4a-000c41e2cdad.html");

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

bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"0.7.3_1")<0) {
  txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.3_1")<0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.2_2,2")<0) {
  txt += 'Package mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.8.a,2")>=0 && revcomp(a:bver, b:"1.8.a3_1,2")<0) {
  txt += 'Package mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mozilla-gtk1");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.2_3")<0) {
  txt += 'Package mozilla-gtk1 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.3")<0) {
  txt += 'Package linux-mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-mozillafirebird");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package linux-mozillafirebird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}