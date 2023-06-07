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
  script_oid("1.3.6.1.4.1.25623.1.0.60820");
  script_version("2022-01-18T14:26:25+0000");
  script_tag(name:"last_modification", value:"2022-01-18 14:26:25 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2007-2435", "CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3655", "CVE-2007-5232", "CVE-2007-5237", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273", "CVE-2007-5274", "CVE-2007-5689", "CVE-2008-0628", "CVE-2008-0657", "CVE-2008-1185", "CVE-2008-1186", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1191", "CVE-2008-1192", "CVE-2008-1193", "CVE-2008-1194", "CVE-2008-1195", "CVE-2008-1196");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200804-20 (sun-jdk, sun-jre-bin, emul-linux-x86-java)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been identified in Sun Java Development Kit
(JDK) and Java Runtime Environment (JRE).");
  script_tag(name:"solution", value:"All Sun JRE users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose 'dev-java/sun-jre-bin'

All Sun JDK users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose 'dev-java/sun-jdk'

All emul-linux-x86-java users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose 'app-emulation/emul-linux-x86-java'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200804-20");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=178851");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=178962");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=183580");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=185256");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=194711");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=212425");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200705-23.xml");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200706-08.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200804-20.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-java/sun-jre-bin", unaffected: make_list("ge 1.6.0.05", "rge 1.5.0.15", "rge 1.4.2.17"), vulnerable: make_list("lt 1.6.0.05"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-java/sun-jdk", unaffected: make_list("ge 1.6.0.05", "rge 1.5.0.15", "rge 1.4.2.17"), vulnerable: make_list("lt 1.6.0.05"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-emulation/emul-linux-x86-java", unaffected: make_list("ge 1.6.0.05", "rge 1.5.0.15", "rge 1.4.2.17"), vulnerable: make_list("lt 1.6.0.05"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
