###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from vuxml or freebsd advisories
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2008 E-Soft Inc. http://www.securityspace.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.54000");
  script_version("2022-01-18T16:34:09+0000");
  script_tag(name:"last_modification", value:"2022-01-18 16:34:09 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-2107", "CVE-2005-2108", "CVE-2005-2109", "CVE-2005-2110");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: wordpress");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: wordpress

CVE-2005-2107
Multiple cross-site scripting (XSS) vulnerabilities in post.php in
WordPress 1.5.1.2 and earlier allow remote attackers to inject
arbitrary web script or HTML via the (1) p or (2) comment parameter.

CVE-2005-2108
SQL injection vulnerability in XMLRPC server in WordPress 1.5.1.2 and
earlier allows remote attackers to execute arbitrary SQL commands via
input that is not filtered in the HTTP_RAW_POST_DATA variable, which
stores the data in an XML file.

CVE-2005-2109
wp-login.php in WordPress 1.5.1.2 and earlier allows remote attackers
to change the content of the forgotten password e-mail message via the
message variable, which is not initialized before use.

CVE-2005-2110
WordPress 1.5.1.2 and earlier allows remote attackers to obtain
sensitive information via (1) a direct request to menu-header.php or a
'1' value in the feed parameter to (2) wp-atom.php, (3) wp-rss.php, or
(4) wp-rss2.php, which reveal the path in an error message.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=112006967221438");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/dca0a345-ed81-11d9-8310-0001020eed82.html");

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

bver = portver(pkg:"wordpress");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.1.3,1")<0) {
  txt += 'Package wordpress version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}