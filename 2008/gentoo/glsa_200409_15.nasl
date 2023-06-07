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
  script_oid("1.3.6.1.4.1.25623.1.0.54671");
  script_cve_id("CVE-2004-0559", "CVE-2004-1468");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2022-01-18T14:26:25+0000");
  script_tag(name:"last_modification", value:"2022-01-18 14:26:25 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200409-15 (Usermin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A vulnerability in the webmail function of Usermin could be used by an
attacker to execute shell code via a specially-crafted e-mail. A bug in
the installation script of Webmin and Usermin also allows a local user to
execute a symlink attack at installation time.");
  script_tag(name:"solution", value:"All Usermin users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=app-admin/usermin-1.090'
    # emerge '>=app-admin/usermin-1.090'

All Webmin users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=app-admin/webmin-1.160'
    # emerge '>=app-admin/webmin-1.160'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200409-15");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=63167");
  script_xref(name:"URL", value:"http://secunia.com/advisories/12488/");
  script_xref(name:"URL", value:"http://www.webmin.com/uchanges.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200409-15.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-admin/usermin", unaffected: make_list("ge 1.090"), vulnerable: make_list("lt 1.090"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-admin/webmin", unaffected: make_list("ge 1.160"), vulnerable: make_list("lt 1.160"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}