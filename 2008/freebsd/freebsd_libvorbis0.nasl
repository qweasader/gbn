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
  script_oid("1.3.6.1.4.1.25623.1.0.61057");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2008-1419", "CVE-2008-1420", "CVE-2008-1423");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: libvorbis");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: libvorbis

CVE-2008-1419
Xiph.org libvorbis 1.2.0 and earlier does not properly handle a zero
value for codebook.dim, which allows remote attackers to cause a
denial of service (crash or infinite loop) or trigger an integer
overflow.

CVE-2008-1420
Integer overflow in residue partition value (aka partvals) evaluation
in Xiph.org libvorbis 1.2.0 and earlier allows remote attackers to
execute arbitrary code via a crafted OGG file, which triggers a heap
overflow.

CVE-2008-1423
Integer overflow in a certain quantvals and quantlist calculation in
Xiph.org libvorbis 1.2.0 and earlier allows remote attackers to cause
a denial of service (crash) or execute arbitrary code via a crafted
OGG file with a large virtual space for its codebook, which triggers a
heap overflow.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2008-0270.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/f5a76faf-244c-11dd-b143-0211d880e350.html");

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

bver = portver(pkg:"libvorbis");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.0_2,3")<0) {
  txt += 'Package libvorbis version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}