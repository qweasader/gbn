###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID 58997463-e012-11dd-a765-0030843d3802
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
  script_oid("1.3.6.1.4.1.25623.1.0.63167");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2009-01-13 22:38:32 +0100 (Tue, 13 Jan 2009)");
  script_cve_id("CVE-2008-5705", "CVE-2008-5706");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: verlihub");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: verlihub

CVE-2008-5705
The cTrigger::DoIt function in src/ctrigger.cpp in the trigger
mechanism in the daemon in Verlihub 0.9.8d-RC2 and earlier, when user
triggers are enabled, allows remote attackers to execute arbitrary
commands via shell metacharacters in an argument.

CVE-2008-5706
The cTrigger::DoIt function in src/ctrigger.cpp in the trigger
mechanism in the daemon in Verlihub 0.9.8d-RC2 and earlier allows
local users to overwrite arbitrary files via a symlink attack on the
/tmp/trigger.tmp temporary file.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/7183");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32420");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32889");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/58997463-e012-11dd-a765-0030843d3802.html");

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

bver = portver(pkg:"verlihub");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.8.d.r2_2,1")<0) {
  txt += 'Package verlihub version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}