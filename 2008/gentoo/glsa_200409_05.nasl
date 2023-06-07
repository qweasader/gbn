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
  script_oid("1.3.6.1.4.1.25623.1.0.54662");
  script_cve_id("CVE-2004-1466");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2022-01-18T14:26:25+0000");
  script_tag(name:"last_modification", value:"2022-01-18 14:26:25 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200409-05 (Gallery)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"The Gallery image upload code contains a temporary file handling
vulnerability which could lead to execution of arbitrary commands.");
  script_tag(name:"solution", value:"All Gallery users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=www-apps/gallery-1.4.4_p2'
    # emerge '>=www-apps/gallery-1.4.4_p2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200409-05");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=60742");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-08/0757.html");
  script_xref(name:"URL", value:"http://gallery.menalto.com/modules.php?op=modload&name=News&file=article&sid=134&mode=thread&order=0&thold=0");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200409-05.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-apps/gallery", unaffected: make_list("ge 1.4.4_p2"), vulnerable: make_list("lt 1.4.4_p2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
