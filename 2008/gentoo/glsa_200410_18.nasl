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
  script_oid("1.3.6.1.4.1.25623.1.0.54709");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0967");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200410-18 (Ghostscript)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple scripts in the Ghostscript package are vulnerable to symlink
attacks, potentially allowing a local user to overwrite arbitrary files
with the rights of the user running the script.");
  script_tag(name:"solution", value:"Ghostscript users on all architectures except PPC should upgrade to the
latest version:

    # emerge sync

    # emerge -pv '>=app-text/ghostscript-7.07.1-r7'
    # emerge '>=app-text/ghostscript-7.07.1-r7'

Ghostscript users on the PPC architecture should upgrade to the latest
stable version on their architecture:

    # emerge sync

    # emerge -pv '>=app-text/ghostscript-7.05.6-r2'
    # emerge '>=app-text/ghostscript-7.05.6-r2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200410-18");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11285");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=66357");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200410-18.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-text/ghostscript", unaffected: make_list("ge 7.07.1-r7", "rge 7.05.6-r2"), vulnerable: make_list("lt 7.07.1-r7"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
