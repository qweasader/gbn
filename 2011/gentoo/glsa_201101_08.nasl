###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
  script_oid("1.3.6.1.4.1.25623.1.0.69044");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-2883", "CVE-2010-2884", "CVE-2010-2887", "CVE-2010-2889", "CVE-2010-2890", "CVE-2010-3619", "CVE-2010-3620", "CVE-2010-3621", "CVE-2010-3622", "CVE-2010-3625", "CVE-2010-3626", "CVE-2010-3627", "CVE-2010-3628", "CVE-2010-3629", "CVE-2010-3630", "CVE-2010-3632", "CVE-2010-3654", "CVE-2010-3656", "CVE-2010-3657", "CVE-2010-3658", "CVE-2010-4091");
  script_name("Gentoo Security Advisory GLSA 201101-08 (acroread)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in Adobe Reader might result in the execution of
    arbitrary code.");
  script_tag(name:"solution", value:"All Adobe Reader users should upgrade to the latest stable version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/acroread-9.4.1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201101-08");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=336508");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=343091");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-21.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-28.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201101-08.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-text/acroread", unaffected: make_list("ge 9.4.1"), vulnerable: make_list("lt 9.4.1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
