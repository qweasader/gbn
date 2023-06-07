###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID 34e0316a-aa91-11df-8c2e-001517289bf8
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
  script_oid("1.3.6.1.4.1.25623.1.0.67860");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2010-08-21 08:54:16 +0200 (Sat, 21 Aug 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-0541");
  script_name("FreeBSD Ports: ruby, ruby+pthreads, ruby+pthreads+oniguruma, ruby+oniguruma");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  ruby
   ruby+pthreads
   ruby+pthreads+oniguruma
   ruby+oniguruma

CVE-2010-0541
Cross-site scripting (XSS) vulnerability in the WEBrick HTTP server in
Ruby in Apple Mac OS X 10.5.8, and 10.6 before 10.6.4, allows remote
attackers to inject arbitrary web script or HTML via a crafted URI
that triggers a UTF-7 error page.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.ruby-lang.org/en/news/2010/08/16/xss-in-webrick-cve-2010-0541/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40895");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/34e0316a-aa91-11df-8c2e-001517289bf8.html");

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

bver = portver(pkg:"ruby");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.*,1")>=0 && revcomp(a:bver, b:"1.8.7.248_3,1")<0) {
  txt += 'Package ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.9.*,1")>=0 && revcomp(a:bver, b:"1.9.1.430,1")<0) {
  txt += 'Package ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ruby+pthreads");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.*,1")>=0 && revcomp(a:bver, b:"1.8.7.248_3,1")<0) {
  txt += 'Package ruby+pthreads version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.9.*,1")>=0 && revcomp(a:bver, b:"1.9.1.430,1")<0) {
  txt += 'Package ruby+pthreads version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ruby+pthreads+oniguruma");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.*,1")>=0 && revcomp(a:bver, b:"1.8.7.248_3,1")<0) {
  txt += 'Package ruby+pthreads+oniguruma version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.9.*,1")>=0 && revcomp(a:bver, b:"1.9.1.430,1")<0) {
  txt += 'Package ruby+pthreads+oniguruma version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ruby+oniguruma");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.*,1")>=0 && revcomp(a:bver, b:"1.8.7.248_3,1")<0) {
  txt += 'Package ruby+oniguruma version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.9.*,1")>=0 && revcomp(a:bver, b:"1.9.1.430,1")<0) {
  txt += 'Package ruby+oniguruma version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}