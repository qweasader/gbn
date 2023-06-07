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
  script_oid("1.3.6.1.4.1.25623.1.0.54576");
  script_cve_id("CVE-2004-0519", "CVE-2004-0521");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2022-04-12T08:46:17+0000");
  script_tag(name:"last_modification", value:"2022-04-12 08:46:17 +0000 (Tue, 12 Apr 2022)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200405-16 (SquirrelMail)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"SquirrelMail is subject to several XSS and one SQL injection vulnerability.");
  script_tag(name:"solution", value:"All SquirrelMail users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv '>=net-mail/squirrelmail-1.4.3_rc1'
    # emerge '>=net-mail/squirrelmail-1.4.3_rc1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200405-16");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=49675");
  script_xref(name:"URL", value:"http://sourceforge.net/mailarchive/forum.php?thread_id=4199060&forum_id=1988");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10246");
  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2000-02.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200405-16.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-mail/squirrelmail", unaffected: make_list("ge 1.4.3_rc1"), vulnerable: make_list("lt 1.4.3_rc1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
