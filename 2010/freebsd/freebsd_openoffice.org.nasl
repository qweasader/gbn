###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID c97d7a37-2233-11df-96dd-001b2134ef46
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
  script_oid("1.3.6.1.4.1.25623.1.0.67053");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2010-03-16 17:25:39 +0100 (Tue, 16 Mar 2010)");
  script_cve_id("CVE-2006-4339", "CVE-2009-0217", "CVE-2009-2493", "CVE-2009-2949", "CVE-2009-2950", "CVE-2009-3301", "CVE-2009-3302");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: openoffice.org");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: openoffice.org

For details on the issues addressed in this update, please visit the
referenced security advisories.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.openoffice.org/security/bulletin.html");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2006-4339.html");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2009-0217.html");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2009-2493.html");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2009-2949.html");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2009-2950.html");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2009-3301-3302.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/c97d7a37-2233-11df-96dd-001b2134ef46.html");

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

bver = portver(pkg:"openoffice.org");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.0")<0) {
  txt += 'Package openoffice.org version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.2.20010101")>=0 && revcomp(a:bver, b:"3.2.20100203")<0) {
  txt += 'Package openoffice.org version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.3.20010101")>=0 && revcomp(a:bver, b:"3.3.20100207")<0) {
  txt += 'Package openoffice.org version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}