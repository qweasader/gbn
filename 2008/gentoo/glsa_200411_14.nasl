###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from Gentoo's XML based advisory
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
  script_oid("1.3.6.1.4.1.25623.1.0.54735");
  script_cve_id("CVE-2004-1034");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2022-01-18T14:26:25+0000");
  script_tag(name:"last_modification", value:"2022-01-18 14:26:25 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200411-14 (kaffeine gxine)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Kaffeine and gxine both contain a buffer overflow that can be exploited
when accessing content from a malicious HTTP server with specially crafted
headers.");
  script_tag(name:"solution", value:"All Kaffeine users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/kaffeine-0.4.3b-r1'

All gxine users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/gxine-0.3.3-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200411-14");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=69663");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=70055");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2004/Oct/1011936.html");
  script_xref(name:"URL", value:"http://sourceforge.net/tracker/index.php?func=detail&aid=1060299&group_id=9655&atid=109655");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200411-14.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"media-video/kaffeine", unaffected: make_list("ge 0.5_rc1-r1", "rge 0.4.3b-r1"), vulnerable: make_list("lt 0.5_rc1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"media-video/gxine", unaffected: make_list("ge 0.3.3-r1"), vulnerable: make_list("lt 0.3.3-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
