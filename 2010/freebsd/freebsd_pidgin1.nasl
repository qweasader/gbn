###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID a2c4d3d5-4c7b-11df-83fb-0015587e2cc1
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
  script_oid("1.3.6.1.4.1.25623.1.0.67360");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2010-05-04 05:52:15 +0200 (Tue, 04 May 2010)");
  script_cve_id("CVE-2010-0277", "CVE-2010-0420", "CVE-2010-0423");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: pidgin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  pidgin
   libpurple

CVE-2010-0277
slp.c in the MSN protocol plugin in libpurple in Pidgin before 2.6.6,
including 2.6.4, and Adium 1.3.8 allows remote attackers to cause a
denial of service (memory corruption and application crash) or
possibly have unspecified other impact via a malformed MSNSLP INVITE
request in an SLP message, a different issue than CVE-2010-0013.

CVE-2010-0420
libpurple in Finch in Pidgin before 2.6.6, when an XMPP multi-user
chat (MUC) room is used, does not properly parse nicknames containing
<br> sequences, which allows remote attackers to cause a denial of
service (application crash) via a crafted nickname.

CVE-2010-0423
gtkimhtml.c in Pidgin before 2.6.6 allows remote attackers to cause a
denial of service (CPU consumption and application hang) by sending
many smileys in a (1) IM or (2) chat.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=43");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38294");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=44");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=45");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/a2c4d3d5-4c7b-11df-83fb-0015587e2cc1.html");

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

bver = portver(pkg:"pidgin");
if(!isnull(bver) && revcomp(a:bver, b:"2.6.6")<0) {
  txt += 'Package pidgin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"libpurple");
if(!isnull(bver) && revcomp(a:bver, b:"2.6.6")<0) {
  txt += 'Package libpurple version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}