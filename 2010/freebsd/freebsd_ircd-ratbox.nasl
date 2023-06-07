###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID 192609c8-0c51-11df-82a0-00248c9b4be7
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
  script_oid("1.3.6.1.4.1.25623.1.0.66819");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2010-02-10 21:51:26 +0100 (Wed, 10 Feb 2010)");
  script_cve_id("CVE-2009-4016", "CVE-2010-0300");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: ircd-ratbox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  ircd-ratbox
   ircd-ratbox-devel

CVE-2009-4016
Integer underflow in the clean_string function in irc_string.c in (1)
IRCD-hybrid 7.2.2 and 7.2.3, (2) ircd-ratbox before 2.2.9, and (3)
oftc-hybrid before 1.6.8, when flatten_links is disabled, allows
remote attackers to execute arbitrary code or cause a denial of
service (daemon crash) via a LINKS command.

CVE-2010-0300
cache.c in ircd-ratbox before 2.2.9 allows remote attackers to cause a
denial of service (NULL pointer dereference and daemon crash) via a
HELP command.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.debian.org/security/2010/dsa-1980");
  script_xref(name:"URL", value:"http://lists.ratbox.org/pipermail/ircd-ratbox/2010-January/000890.html");
  script_xref(name:"URL", value:"http://lists.ratbox.org/pipermail/ircd-ratbox/2010-January/000891.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/192609c8-0c51-11df-82a0-00248c9b4be7.html");

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

bver = portver(pkg:"ircd-ratbox");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.9")<0) {
  txt += 'Package ircd-ratbox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ircd-ratbox-devel");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.6")<0) {
  txt += 'Package ircd-ratbox-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}