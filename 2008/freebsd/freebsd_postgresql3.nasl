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
  script_oid("1.3.6.1.4.1.25623.1.0.57256");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0244", "CVE-2005-0245", "CVE-2005-0246");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: postgresql, postgresql-server, ja-postgresql");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  postgresql
   postgresql-server
   ja-postgresql

CVE-2005-0244
PostgreSQL 8.0.0 and earlier allows local users to bypass the EXECUTE
permission check for functions by using the CREATE AGGREGATE command.

CVE-2005-0245
Buffer overflow in gram.y for PostgreSQL 8.0.0 and earlier may allow
attackers to execute arbitrary code via a large number of arguments to
a refcursor function (gram.y), which leads to a heap-based buffer
overflow, a different vulnerability than CVE-2005-0247.

CVE-2005-0246
The intagg contrib module for PostgreSQL 8.0.0 and earlier allows
attackers to cause a denial of service (crash) via crafted arrays.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/12948");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/65c8ecf9-2adb-11db-a6e2-000e0c2e438a.html");

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

bver = portver(pkg:"postgresql");
if(!isnull(bver) && revcomp(a:bver, b:"7.2")>=0 && revcomp(a:bver, b:"7.2.7")<0) {
  txt += 'Package postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.3")>=0 && revcomp(a:bver, b:"7.3.9")<0) {
  txt += 'Package postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.4")>=0 && revcomp(a:bver, b:"7.4.7")<0) {
  txt += 'Package postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.0.0")>=0 && revcomp(a:bver, b:"8.0.1")<0) {
  txt += 'Package postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"postgresql-server");
if(!isnull(bver) && revcomp(a:bver, b:"7.2")>=0 && revcomp(a:bver, b:"7.2.7")<0) {
  txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.3")>=0 && revcomp(a:bver, b:"7.3.9")<0) {
  txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.4")>=0 && revcomp(a:bver, b:"7.4.7")<0) {
  txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.0.0")>=0 && revcomp(a:bver, b:"8.0.1")<0) {
  txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-postgresql");
if(!isnull(bver) && revcomp(a:bver, b:"7.2")>=0 && revcomp(a:bver, b:"7.2.7")<0) {
  txt += 'Package ja-postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.3")>=0 && revcomp(a:bver, b:"7.3.9")<0) {
  txt += 'Package ja-postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.4")>=0 && revcomp(a:bver, b:"7.4.7")<0) {
  txt += 'Package ja-postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.0.0")>=0 && revcomp(a:bver, b:"8.0.1")<0) {
  txt += 'Package ja-postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}