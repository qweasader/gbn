###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID 94c0ac4f-9388-11e1-b242-00262d5ed8ee
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2012 E-Soft Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.71386");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-3078", "CVE-2011-3079", "CVE-2011-3080", "CVE-2011-3081", "CVE-2012-1521");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2012-05-31 11:53:51 -0400 (Thu, 31 May 2012)");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: chromium

CVE-2011-3078
Use-after-free vulnerability in Google Chrome before 18.0.1025.168
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the floating of
elements, a different vulnerability than CVE-2011-3081.
CVE-2011-3079
The Inter-process Communication (IPC) implementation in Google Chrome
before 18.0.1025.168 does not properly validate messages, which has
unspecified impact and attack vectors.
CVE-2011-3080
Race condition in the Inter-process Communication (IPC) implementation
in Google Chrome before 18.0.1025.168 allows attackers to bypass
intended sandbox restrictions via unspecified vectors.
CVE-2011-3081
Use-after-free vulnerability in Google Chrome before 18.0.1025.168
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the floating of
elements, a different vulnerability than CVE-2011-3078.
CVE-2012-1521
Use-after-free vulnerability in the XML parser in Google Chrome before
18.0.1025.168 allows remote attackers to cause a denial of service or
possibly have unspecified other impact via unknown vectors.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/94c0ac4f-9388-11e1-b242-00262d5ed8ee.html");

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

bver = portver(pkg:"chromium");
if(!isnull(bver) && revcomp(a:bver, b:"18.0.1025.168")<0) {
  txt += "Package chromium version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}