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
  script_oid("1.3.6.1.4.1.25623.1.0.60453");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2008-0504", "CVE-2008-0505", "CVE-2008-0506");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: coppermine");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: coppermine

CVE-2008-0504
Multiple SQL injection vulnerabilities in Coppermine Photo Gallery
(CPG) before 1.4.15 allow remote attackers to execute arbitrary SQL
commands via unspecified parameters to (1) util.php and (2)
reviewcom.php.  NOTE: some of these details are obtained from third
party information.

CVE-2008-0505
Multiple cross-site scripting (XSS) vulnerabilities in
docs/showdoc.php in Coppermine Photo Gallery (CPG) before 1.4.15 allow
remote attackers to inject arbitrary web script or HTML via the (1) h
and (2) t parameters.  NOTE: some of these details are obtained from
third party information.

CVE-2008-0506
include/imageObjectIM.class.php in Coppermine Photo Gallery (CPG)
before 1.4.15, when the ImageMagick picture processing method is
configured, allows remote attackers to execute arbitrary commands via
shell metacharacters in the (1) quality, (2) angle, or (3) clipval
parameter to picEditor.php.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://coppermine-gallery.net/forum/index.php?topic=48106.0");
  script_xref(name:"URL", value:"http://coppermine-gallery.net/forum/index.php?topic=50103.0");
  script_xref(name:"URL", value:"http://secunia.com/advisories/28682/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/9f581778-e3d4-11dc-bb89-000bcdc1757a.html");

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

bver = portver(pkg:"coppermine");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.15")<0) {
  txt += 'Package coppermine version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}