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
  script_oid("1.3.6.1.4.1.25623.1.0.52193");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: enscript-a4, enscript-letter, enscript-letterdj");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  enscript-a4
   enscript-letter
   enscript-letterdj

CVE-2004-1184
The EPSF pipe support in enscript 1.6.3 allows remote attackers or
local users to execute arbitrary commands via shell metacharacters.

CVE-2004-1185
Enscript 1.6.3 does not sanitize filenames, which allows remote
attackers or local users to execute arbitrary commands via crafted
filenames.

CVE-2004-1186
Multiple buffer overflows in enscript 1.6.3 allow remote attackers or
local users to cause a denial of service (application crash).");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200502-03.xml");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/72da8af6-7c75-11d9-8cc5-000854d03344.html");

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

bver = portver(pkg:"enscript-a4");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4_1")<0) {
  txt += 'Package enscript-a4 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"enscript-letter");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4_1")<0) {
  txt += 'Package enscript-letter version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"enscript-letterdj");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4_1")<0) {
  txt += 'Package enscript-letterdj version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}