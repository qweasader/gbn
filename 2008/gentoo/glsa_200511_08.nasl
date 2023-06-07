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
  script_oid("1.3.6.1.4.1.25623.1.0.55857");
  script_version("2022-01-18T14:26:25+0000");
  script_tag(name:"last_modification", value:"2022-01-18 14:26:25 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-3054", "CVE-2005-3319", "CVE-2005-3388", "CVE-2005-3389", "CVE-2005-3390", "CVE-2005-3391", "CVE-2005-3392");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200511-08 (PHP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"PHP suffers from multiple issues, resulting in security functions bypass,
local Denial of service, cross-site scripting or PHP variables overwrite.");
  script_tag(name:"solution", value:"All PHP users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose dev-php/php

All mod_php users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose dev-php/mod_php

All php-cgi users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose dev-php/php-cgi");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200511-08");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=107602");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=111032");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200511-08.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-php/php", unaffected: make_list("rge 4.3.11-r4", "ge 4.4.0-r4"), vulnerable: make_list("lt 4.4.0-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-php/mod_php", unaffected: make_list("rge 4.3.11-r4", "ge 4.4.0-r8"), vulnerable: make_list("lt 4.4.0-r8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-php/php-cgi", unaffected: make_list("rge 4.3.11-r5", "ge 4.4.0-r5"), vulnerable: make_list("lt 4.4.0-r5"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
