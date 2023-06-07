# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:051 (libpng)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2009 E-Soft Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.63440");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-03-02 19:11:09 +0100 (Mon, 02 Mar 2009)");
  script_cve_id("CVE-2008-3964", "CVE-2008-5907", "CVE-2009-0040");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:051 (libpng)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.0|2008\.1|2009\.0|3\.0|4\.0|2\.0)");
  script_tag(name:"insight", value:"A number of vulnerabilities have been found and corrected in libpng:

Fixed 1-byte buffer overflow in pngpread.c (CVE-2008-3964). This was
already fixed in Mandriva Linux 2009.0.

Fix the function png_check_keyword() that allowed setting arbitrary
bytes in the process memory to 0 (CVE-2008-5907).

Fix a potential DoS (Denial of Service) or to potentially compromise
an application using the library (CVE-2009-0040).

The updated packages have been patched to prevent this.

Affected: 2008.0, 2008.1, 2009.0, Corporate 3.0, Corporate 4.0,
          Multi Network Firewall 2.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:051");
  script_tag(name:"summary", value:"The remote host is missing an update to libpng
announced via advisory MDVSA-2009:051.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libpng3", rpm:"libpng3~1.2.22~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.2.22~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-source", rpm:"libpng-source~1.2.22~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-static-devel", rpm:"libpng-static-devel~1.2.22~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64png3", rpm:"lib64png3~1.2.22~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64png-devel", rpm:"lib64png-devel~1.2.22~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64png-static-devel", rpm:"lib64png-static-devel~1.2.22~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng3", rpm:"libpng3~1.2.25~2.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.2.25~2.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-source", rpm:"libpng-source~1.2.25~2.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-static-devel", rpm:"libpng-static-devel~1.2.25~2.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64png3", rpm:"lib64png3~1.2.25~2.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64png-devel", rpm:"lib64png-devel~1.2.25~2.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64png-static-devel", rpm:"lib64png-static-devel~1.2.25~2.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng3", rpm:"libpng3~1.2.31~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.2.31~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-source", rpm:"libpng-source~1.2.31~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-static-devel", rpm:"libpng-static-devel~1.2.31~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64png3", rpm:"lib64png3~1.2.31~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64png-devel", rpm:"lib64png-devel~1.2.31~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64png-static-devel", rpm:"lib64png-static-devel~1.2.31~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng3", rpm:"libpng3~1.2.5~10.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng3-devel", rpm:"libpng3-devel~1.2.5~10.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng3-static-devel", rpm:"libpng3-static-devel~1.2.5~10.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64png3", rpm:"lib64png3~1.2.5~10.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64png3-devel", rpm:"lib64png3-devel~1.2.5~10.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64png3-static-devel", rpm:"lib64png3-static-devel~1.2.5~10.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng3", rpm:"libpng3~1.2.8~1.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng3-devel", rpm:"libpng3-devel~1.2.8~1.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng3-static-devel", rpm:"libpng3-static-devel~1.2.8~1.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64png3", rpm:"lib64png3~1.2.8~1.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64png3-devel", rpm:"lib64png3-devel~1.2.8~1.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64png3-static-devel", rpm:"lib64png3-static-devel~1.2.8~1.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng3", rpm:"libpng3~1.2.5~10.11.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng3-devel", rpm:"libpng3-devel~1.2.5~10.11.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng3-static-devel", rpm:"libpng3-static-devel~1.2.5~10.11.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
