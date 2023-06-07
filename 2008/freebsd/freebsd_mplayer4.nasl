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
  script_oid("1.3.6.1.4.1.25623.1.0.56510");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-1502");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("mplayer -- Multiple integer overflows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  mplayer
   mplayer-esound
   mplayer-gtk
   mplayer-gtk2
   mplayer-gtk-esound
   mplayer-gtk2-esound

CVE-2006-1502
Multiple integer overflows in MPlayer 1.0pre7try2 allow remote
attackers to cause a denial of service and trigger heap-based buffer
overflows via (1) a certain ASF file handled by asfheader.c that
causes the asf_descrambling function to be passed a negative integer
after the conversion from a char to an int or (2) an AVI file with a
crafted wLongsPerEntry or nEntriesInUse value in the indx chunk, which
is handled in aviheader.c.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.xfocus.org/advisories/200603/11.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17295");
  script_xref(name:"URL", value:"http://secunia.com/advisories/19418/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/c7526a14-c4dc-11da-9699-00123ffe8333.html");

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

bver = portver(pkg:"mplayer");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.7_12")<0) {
  txt += 'Package mplayer version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.7_12")<0) {
  txt += 'Package mplayer-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.7_12")<0) {
  txt += 'Package mplayer-gtk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.7_12")<0) {
  txt += 'Package mplayer-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.7_12")<0) {
  txt += 'Package mplayer-gtk-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk2-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.7_12")<0) {
  txt += 'Package mplayer-gtk2-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}