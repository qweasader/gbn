# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:101 (xpdf)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2009 E-Soft Inc. http://www.securityspace.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.63915");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-05-05 16:00:35 +0200 (Tue, 05 May 2009)");
  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0800", "CVE-2009-0799", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:101 (xpdf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.0|2008\.1|2009\.0|3\.0|4\.0)");
  script_tag(name:"insight", value:"Multiple buffer overflows in the JBIG2 decoder allows remote
attackers to cause a denial of service (crash) via a crafted PDF file
(CVE-2009-0146).

Multiple integer overflows in the JBIG2 decoder allows remote
attackers to cause a denial of service (crash) via a crafted PDF file
(CVE-2009-0147).

An integer overflow in the JBIG2 decoder has unspecified
impact. (CVE-2009-0165).

A free of uninitialized memory flaw in the JBIG2 decoder allows
remote to cause a denial of service (crash) via a crafted PDF file
(CVE-2009-0166).

Multiple input validation flaws in the JBIG2 decoder allows
remote attackers to execute arbitrary code via a crafted PDF file
(CVE-2009-0800).

An out-of-bounds read flaw in the JBIG2 decoder allows remote
attackers to cause a denial of service (crash) via a crafted PDF file
(CVE-2009-0799).

An integer overflow in the JBIG2 decoder allows remote attackers to
execute arbitrary code via a crafted PDF file (CVE-2009-1179).

A free of invalid data flaw in the JBIG2 decoder allows remote
attackers to execute arbitrary code via a crafted PDF (CVE-2009-1180).

A NULL pointer dereference flaw in the JBIG2 decoder allows remote
attackers to cause denial of service (crash) via a crafted PDF file
(CVE-2009-1181).

Multiple buffer overflows in the JBIG2 MMR decoder allows remote
attackers to cause denial of service or to execute arbitrary code
via a crafted PDF file (CVE-2009-1182, CVE-2009-1183).

This update provides fixes for that vulnerabilities.

Affected: 2008.0, 2008.1, 2009.0, Corporate 3.0, Corporate 4.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:101");
  script_tag(name:"summary", value:"The remote host is missing an update to xpdf
announced via advisory MDVSA-2009:101.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~3.02~8.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf-common", rpm:"xpdf-common~3.02~8.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf-tools", rpm:"xpdf-tools~3.02~8.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~3.02~10.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf-common", rpm:"xpdf-common~3.02~10.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~3.02~12.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf-common", rpm:"xpdf-common~3.02~12.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~3.02~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf-tools", rpm:"xpdf-tools~3.02~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~3.02~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf-tools", rpm:"xpdf-tools~3.02~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
