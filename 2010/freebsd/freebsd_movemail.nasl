###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID f6b6beaa-4e0e-11df-83fb-0015587e2cc1
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
  script_oid("1.3.6.1.4.1.25623.1.0.67356");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2010-05-04 05:52:15 +0200 (Tue, 04 May 2010)");
  script_cve_id("CVE-2010-0825");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: movemail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  movemail
   emacs
   xemacs
   xemacs-devel
   xemacs-mule
   zh-xemacs-mule
   ja-xemacs-mule-canna
   xemacs-devel-mule
   xemacs-devel-mule-xft

CVE-2010-0825
lib-src/movemail.c in movemail in emacs 22 and 23 allows local users
to read, modify, or delete arbitrary mailbox files via a symlink
attack, related to improper file-permission checks.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39155");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/USN-919-1");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0734");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57457");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+bug/531569");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/f6b6beaa-4e0e-11df-83fb-0015587e2cc1.html");

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

bver = portver(pkg:"movemail");
if(!isnull(bver) && revcomp(a:bver, b:"1.0")<=0) {
  txt += 'Package movemail version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"emacs");
if(!isnull(bver) && revcomp(a:bver, b:"21.3_14")<=0) {
  txt += 'Package emacs version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"22.3_1,1")>=0 && revcomp(a:bver, b:"22.3_4,1")<=0) {
  txt += 'Package emacs version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"23.1")>=0 && revcomp(a:bver, b:"23.1_5,1")<=0) {
  txt += 'Package emacs version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"xemacs");
if(!isnull(bver) && revcomp(a:bver, b:"21.4.22_4")<=0) {
  txt += 'Package xemacs version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"xemacs-devel");
if(!isnull(bver) && revcomp(a:bver, b:"21.5.b28_8,1")<=0) {
  txt += 'Package xemacs-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"xemacs-mule");
if(!isnull(bver) && revcomp(a:bver, b:"21.4.21_6")<=0) {
  txt += 'Package xemacs-mule version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zh-xemacs-mule");
if(!isnull(bver) && revcomp(a:bver, b:"21.4.21_6")<=0) {
  txt += 'Package zh-xemacs-mule version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-xemacs-mule-canna");
if(!isnull(bver) && revcomp(a:bver, b:"21.4.21_6")<=0) {
  txt += 'Package ja-xemacs-mule-canna version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"xemacs-devel-mule");
if(!isnull(bver) && revcomp(a:bver, b:"21.5.b28_10")<=0) {
  txt += 'Package xemacs-devel-mule version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"xemacs-devel-mule-xft");
if(!isnull(bver) && revcomp(a:bver, b:"21.5.b28_10")<=0) {
  txt += 'Package xemacs-devel-mule-xft version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}