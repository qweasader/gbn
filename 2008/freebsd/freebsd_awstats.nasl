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
  script_oid("1.3.6.1.4.1.25623.1.0.52186");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0362", "CVE-2005-0363", "CVE-2005-0435", "CVE-2005-0436", "CVE-2005-0437", "CVE-2005-0438");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: awstats");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: awstats

CVE-2005-0362
awstats.pl in AWStats 6.2 allows remote attackers to execute arbitrary
commands via shell metacharacters in the (1) 'pluginmode', (2)
'loadplugin', or (3) 'noloadplugin' parameters.

CVE-2005-0363
awstats.pl in AWStats 4.0 and 6.2 allows remote attackers to execute
arbitrary commands via shell metacharacters in the config parameter.

CVE-2005-0435
awstats.pl in AWStats 6.3 and 6.4 allows remote attackers to read
server web logs by setting the loadplugin and pluginmode parameters to
rawlog.

CVE-2005-0436
Direct code injection vulnerability in awstats.pl in AWStats 6.3 and
6.4 allows remote attackers to execute portions of Perl code via the
PluginMode parameter.

CVE-2005-0437
Directory traversal vulnerability in awstats.pl in AWStats 6.3 and 6.4
allows remote attackers to include arbitrary Perl modules via .. (dot
dot) sequences in the loadplugin parameter.

CVE-2005-0438
awstats.pl in AWStats 6.3 and 6.4 allows remote attackers to obtain
sensitive information by setting the debug parameter.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://awstats.sourceforge.net/docs/awstats_changelog.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12543");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12545");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=294488");
  script_xref(name:"URL", value:"http://packetstormsecurity.nl/0501-exploits/AWStatsVulnAnalysis.pdf");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=110840530924124");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/fdad8a87-7f94-11d9-a9e7-0001020eed82.html");

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

bver = portver(pkg:"awstats");
if(!isnull(bver) && revcomp(a:bver, b:"6.4")<0) {
  txt += 'Package awstats version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}