# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:096-1 (printer-drivers)
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
  script_oid("1.3.6.1.4.1.25623.1.0.63912");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-05-05 16:00:35 +0200 (Tue, 05 May 2009)");
  script_cve_id("CVE-2007-6725", "CVE-2009-0583", "CVE-2009-0584", "CVE-2009-0792");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:096-1 (printer-drivers)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_3\.0");
  script_tag(name:"insight", value:"A buffer underflow in Ghostscript's CCITTFax decoding filter allows
remote attackers to cause denial of service and possibly to execute
arbitrary by using a crafted PDF file (CVE-2007-6725).

Multiple integer overflows in Ghostscript's International Color
Consortium Format Library (icclib) allows attackers to cause denial
of service (heap-based buffer overflow and application crash) and
possibly execute arbitrary code by using either a PostScript or PDF
file with crafte embedded images (CVE-2009-0583, CVE-2009-0584).

Multiple integer overflows in Ghostscript's International Color
Consortium Format Library (icclib) allows attackers to cause denial
of service (heap-based buffer overflow and application crash) and
possibly execute arbitrary code by using either a PostScript or PDF
file with crafte embedded images. Note: this issue exists because of
an incomplete fix for CVE-2009-0583 (CVE-2009-0792).

This update provides fixes for that vulnerabilities.

Update:

The previous update went with a wrong require version of perl-base
in the foomatic-db-engine package. It is fixed on this update.

Affected: Corporate 3.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:096-1");
  script_tag(name:"summary", value:"The remote host is missing an update to printer-drivers
announced via advisory MDVSA-2009:096-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"cups-drivers", rpm:"cups-drivers~1.1~138.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"foomatic-db", rpm:"foomatic-db~3.0.1~0.20040828.1.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"foomatic-db-engine", rpm:"foomatic-db-engine~3.0.1~0.20040828.1.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"foomatic-filters", rpm:"foomatic-filters~3.0.1~0.20040828.1.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~7.07~19.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-module-X", rpm:"ghostscript-module-X~7.07~19.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gimpprint", rpm:"gimpprint~4.2.7~2.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgimpprint1", rpm:"libgimpprint1~4.2.7~2.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgimpprint1-devel", rpm:"libgimpprint1-devel~4.2.7~2.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libijs0", rpm:"libijs0~0.34~76.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libijs0-devel", rpm:"libijs0-devel~0.34~76.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"printer-filters", rpm:"printer-filters~1.0~138.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"printer-testpages", rpm:"printer-testpages~1.0~138.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"printer-utils", rpm:"printer-utils~1.0~138.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gimpprint1", rpm:"lib64gimpprint1~4.2.7~2.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gimpprint1-devel", rpm:"lib64gimpprint1-devel~4.2.7~2.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ijs0", rpm:"lib64ijs0~0.34~76.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ijs0-devel", rpm:"lib64ijs0-devel~0.34~76.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
