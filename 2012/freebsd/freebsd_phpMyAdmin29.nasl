###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID 1f6ee708-0d22-11e1-b5bd-14dae938ec40
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
  script_oid("1.3.6.1.4.1.25623.1.0.70603");
  script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_cve_id("CVE-2011-4107");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_version("2022-01-18T07:59:01+0000");
  script_name("FreeBSD Ports: phpMyAdmin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: phpMyAdmin

CVE-2011-4107
The simplexml_load_string function in the XML import plug-in
(libraries/import/xml.php) in phpMyAdmin 3.4.x before 3.4.7.1 and
3.3.x before 3.3.10.5 allows remote authenticated users to read
arbitrary files via XML data containing external entity references,
aka an XML external entity (XXE) injection attack.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-17.php");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/1f6ee708-0d22-11e1-b5bd-14dae938ec40.html");

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

bver = portver(pkg:"phpMyAdmin");
if(!isnull(bver) && revcomp(a:bver, b:"3.4")>0 && revcomp(a:bver, b:"3.4.7.1")<0) {
  txt += 'Package phpMyAdmin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.3.10.5")<0) {
  txt += 'Package phpMyAdmin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}