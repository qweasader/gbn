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
  script_oid("1.3.6.1.4.1.25623.1.0.52995");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2002-0029", "CVE-2004-0083", "CVE-2004-0084", "CVE-2004-0106", "CVE-2004-0687", "CVE-2004-0688", "CVE-2004-0692", "CVE-2004-0914");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: linux_base");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: linux_base

A number of vulnerabilities have been resolved in the
above package. For details of the issues resolved, please
visit the referenced CVE notices.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://fedoralegacy.org/updates/RH7.3/2004-10-23-FLSA_2004_1947__Updated_glibc_packages_fix_flaws.html");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2004-059.html");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2004-478.html");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2004-612.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/bf2e7483-d3fa-440d-8c6e-8f1f2f018818.html");

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

bver = portver(pkg:"linux_base");
if(!isnull(bver) && revcomp(a:bver, b:"7.3")<0) {
  txt += 'Package linux_base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}