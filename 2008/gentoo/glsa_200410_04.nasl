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
  script_oid("1.3.6.1.4.1.25623.1.0.54695");
  script_version("2022-01-18T14:26:25+0000");
  script_tag(name:"last_modification", value:"2022-01-18 14:26:25 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Gentoo Security Advisory GLSA 200410-04 (PHP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Two bugs in PHP may allow the disclosure of portions of memory and allow
remote attackers to upload files to arbitrary locations.");
  script_tag(name:"solution", value:"All PHP, mod_php and php-cgi users should upgrade to the latest stable
version:

    # emerge sync

    # emerge -pv '>=dev-php/php-4.3.9'
    # emerge '>=dev-php/php-4.3.9'

    # emerge -pv '>=dev-php/mod_php-4.3.9'
    # emerge '>=dev-php/mod_php-4.3.9'

    # emerge -pv '>=dev-php/php-cgi-4.3.9'
    # emerge '>=dev-php/php-cgi-4.3.9'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200410-04");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=64223");
  script_xref(name:"URL", value:"http://secunia.com/advisories/12560/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/375294");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/375370");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200410-04.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-php/php", unaffected: make_list("ge 4.3.9"), vulnerable: make_list("lt 4.3.9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-php/mod_php", unaffected: make_list("ge 4.3.9"), vulnerable: make_list("lt 4.3.9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-php/php-cgi", unaffected: make_list("ge 4.3.9"), vulnerable: make_list("lt 4.3.9"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}