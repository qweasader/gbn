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
  script_oid("1.3.6.1.4.1.25623.1.0.54677");
  script_version("2022-01-18T14:26:25+0000");
  script_tag(name:"last_modification", value:"2022-01-18 14:26:25 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0747", "CVE-2004-0748", "CVE-2004-0751", "CVE-2004-0786", "CVE-2004-0809");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Gentoo Security Advisory GLSA 200409-21 (apache)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Several vulnerabilities have been found in Apache 2 and mod_dav for Apache
1.3 which could allow a remote attacker to cause a Denial of Service or a
local user to get escalated privileges.");
  script_tag(name:"solution", value:"All Apache 2 users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=net-www/apache-2.0.51'
    # emerge '>=net-www/apache-2.0.51'

All mod_dav users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=net-www/mod_dav-1.0.3-r2'
    # emerge '>=net-www/mod_dav-1.0.3-r2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200409-21");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=62626");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=63948");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=64145");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200409-21.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-www/apache", unaffected: make_list("ge 2.0.51", "lt 2.0"), vulnerable: make_list("lt 2.0.51"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/mod_dav", unaffected: make_list("ge 1.0.3-r2"), vulnerable: make_list("le 1.0.3-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
