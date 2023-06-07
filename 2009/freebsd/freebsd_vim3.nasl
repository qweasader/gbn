###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID 0e1e3789-d87f-11dd-8ecd-00163e000016
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2009 E-Soft Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.63091");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-01-02 18:22:54 +0100 (Fri, 02 Jan 2009)");
  script_cve_id("CVE-2008-3076");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: vim, vim-lite, vim-gtk2, vim-gnome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  vim
   vim-lite
   vim-gtk2
   vim-gnome

CVE-2008-3076
** RESERVED **
This candidate has been reserved by an organization or individual that
will use it when announcing a new security problem.  When the
candidate has been publicized, the details for this candidate will be
provided.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.rdancer.org/vulnerablevim-netrw.html");
  script_xref(name:"URL", value:"http://www.rdancer.org/vulnerablevim-netrw.v2.html");
  script_xref(name:"URL", value:"http://www.rdancer.org/vulnerablevim-netrw.v5.html");
  script_xref(name:"URL", value:"http://www.rdancer.org/vulnerablevim-netrw-credentials-dis.html");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2008/10/16/2");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/0e1e3789-d87f-11dd-8ecd-00163e000016.html");

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

bver = portver(pkg:"vim");
if(!isnull(bver) && revcomp(a:bver, b:"7.0")>=0 && revcomp(a:bver, b:"7.2")<0) {
  txt += 'Package vim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"vim-lite");
if(!isnull(bver) && revcomp(a:bver, b:"7.0")>=0 && revcomp(a:bver, b:"7.2")<0) {
  txt += 'Package vim-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"vim-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"7.0")>=0 && revcomp(a:bver, b:"7.2")<0) {
  txt += 'Package vim-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"vim-gnome");
if(!isnull(bver) && revcomp(a:bver, b:"7.0")>=0 && revcomp(a:bver, b:"7.2")<0) {
  txt += 'Package vim-gnome version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}