###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from VID 309542b5-50b9-11e1-b0d8-00151735203a
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
  script_oid("1.3.6.1.4.1.25623.1.0.70734");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2012-0448", "CVE-2012-0440");
  script_version("2022-01-18T07:59:01+0000");
  script_tag(name:"last_modification", value:"2022-01-18 07:59:01 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2012-02-12 07:27:19 -0500 (Sun, 12 Feb 2012)");
  script_name("FreeBSD Ports: bugzilla");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: bugzilla

CVE-2012-0448
Bugzilla 2.x and 3.x before 3.4.14, 3.5.x and 3.6.x before 3.6.8,
3.7.x and 4.0.x before 4.0.4, and 4.1.x and 4.2.x before 4.2rc2 does
not reject non-ASCII characters in e-mail addresses of new user
accounts, which makes it easier for remote authenticated users to
spoof other user accounts by choosing a similar e-mail address.

CVE-2012-0440
Cross-site request forgery (CSRF) vulnerability in jsonrpc.cgi in
Bugzilla 3.5.x and 3.6.x before 3.6.8, 3.7.x and 4.0.x before 4.0.4,
and 4.1.x and 4.2.x before 4.2rc2 allows remote attackers to hijack
the authentication of arbitrary users for requests that use the
JSON-RPC API.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=714472");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=718319");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/309542b5-50b9-11e1-b0d8-00151735203a.html");

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

bver = portver(pkg:"bugzilla");
if(!isnull(bver) && revcomp(a:bver, b:"2.4")>=0 && revcomp(a:bver, b:"3.6.8")<0) {
  txt += 'Package bugzilla version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"4.0")>=0 && revcomp(a:bver, b:"4.0.4")<0) {
  txt += 'Package bugzilla version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}