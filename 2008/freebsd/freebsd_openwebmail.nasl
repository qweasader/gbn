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
  script_oid("1.3.6.1.4.1.25623.1.0.52436");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0519");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: openwebmail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  openwebmail
   ilohamail

CVE-2004-0519
Multiple cross-site scripting (XSS) vulnerabilities in SquirrelMail
1.4.2 allow remote attackers to execute arbitrary script as other
users and possibly steal authentication information via multiple
attack vectors, including the mailbox parameter in compose.php.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-2.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10246");
  script_xref(name:"URL", value:"http://www.freebsd.org/ports/portaudit/89a0de27-bf66-11d8-a252-02e0185c0b53.html");
  script_xref(name:"URL", value:"http://www.freebsd.org/ports/portaudit/911f1b19-bd20-11d8-84f9-000bdb1444a4.html");
  script_xref(name:"URL", value:"http://www.freebsd.org/ports/portaudit/c3e56efa-c42f-11d8-864c-02e0185c0b53.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/c5519420-cec2-11d8-8898-000d6111a684.html");

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

bver = portver(pkg:"openwebmail");
if(!isnull(bver) && revcomp(a:bver, b:"2.32")<=0) {
  txt += 'Package openwebmail version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ilohamail");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.13")<0) {
  txt += 'Package ilohamail version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}