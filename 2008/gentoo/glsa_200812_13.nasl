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
  script_oid("1.3.6.1.4.1.25623.1.0.62962");
  script_version("2022-01-18T14:26:25+0000");
  script_tag(name:"last_modification", value:"2022-01-18 14:26:25 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-12-23 18:28:16 +0100 (Tue, 23 Dec 2008)");
  script_cve_id("CVE-2008-2237", "CVE-2008-2238", "CVE-2008-4937");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200812-13 (openoffice openoffice-bin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in OpenOffice.org might allow for user-assisted
execution of arbitrary code or symlink attacks.");
  script_tag(name:"solution", value:"All OpenOffice.org users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-3.0.0'

All OpenOffice.org binary users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-bin-3.0.0'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200812-13");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=235824");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=244995");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200812-13.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-office/openoffice", unaffected: make_list("ge 3.0.0"), vulnerable: make_list("lt 3.0.0"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice-bin", unaffected: make_list("ge 3.0.0"), vulnerable: make_list("lt 3.0.0"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
