# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:258 (openssl)
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
  script_oid("1.3.6.1.4.1.25623.1.0.65734");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-10-13 18:25:40 +0200 (Tue, 13 Oct 2009)");
  script_cve_id("CVE-2009-2409");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:258 (openssl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|2009\.1|3\.0|4\.0|mes5|2\.0)");
  script_tag(name:"insight", value:"A regression was found with the self signed certificate signatures
checking after applying the fix for CVE-2009-2409. An upstream patch
has been applied to address this issue.

Affected: 2008.1, 2009.0, 2009.1, Corporate 3.0, Corporate 4.0,
          Enterprise Server 5.0, Multi Network Firewall 2.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:258");
  script_xref(name:"URL", value:"http://marc.info/?l=openssl-cvs&m=124508133203041&w=2");
  script_tag(name:"summary", value:"The remote host is missing an update to openssl
announced via advisory MDVSA-2009:258.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libopenssl0.9.8", rpm:"libopenssl0.9.8~0.9.8g~4.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8-devel", rpm:"libopenssl0.9.8-devel~0.9.8g~4.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8-static-devel", rpm:"libopenssl0.9.8-static-devel~0.9.8g~4.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8g~4.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8", rpm:"lib64openssl0.9.8~0.9.8g~4.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-devel", rpm:"lib64openssl0.9.8-devel~0.9.8g~4.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-static-devel", rpm:"lib64openssl0.9.8-static-devel~0.9.8g~4.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8", rpm:"libopenssl0.9.8~0.9.8h~3.5mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8-devel", rpm:"libopenssl0.9.8-devel~0.9.8h~3.5mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8-static-devel", rpm:"libopenssl0.9.8-static-devel~0.9.8h~3.5mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8h~3.5mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8", rpm:"lib64openssl0.9.8~0.9.8h~3.5mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-devel", rpm:"lib64openssl0.9.8-devel~0.9.8h~3.5mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-static-devel", rpm:"lib64openssl0.9.8-static-devel~0.9.8h~3.5mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8", rpm:"libopenssl0.9.8~0.9.8k~1.3mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8-devel", rpm:"libopenssl0.9.8-devel~0.9.8k~1.3mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8-static-devel", rpm:"libopenssl0.9.8-static-devel~0.9.8k~1.3mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8k~1.3mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8", rpm:"lib64openssl0.9.8~0.9.8k~1.3mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-devel", rpm:"lib64openssl0.9.8-devel~0.9.8k~1.3mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-static-devel", rpm:"lib64openssl0.9.8-static-devel~0.9.8k~1.3mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.7", rpm:"libopenssl0.9.7~0.9.7c~3.12.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.7-devel", rpm:"libopenssl0.9.7-devel~0.9.7c~3.12.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.7-static-devel", rpm:"libopenssl0.9.7-static-devel~0.9.7c~3.12.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.7c~3.12.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.7", rpm:"lib64openssl0.9.7~0.9.7c~3.12.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.7-devel", rpm:"lib64openssl0.9.7-devel~0.9.7c~3.12.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.7-static-devel", rpm:"lib64openssl0.9.7-static-devel~0.9.7c~3.12.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.7", rpm:"libopenssl0.9.7~0.9.7g~2.11.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.7-devel", rpm:"libopenssl0.9.7-devel~0.9.7g~2.11.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.7-static-devel", rpm:"libopenssl0.9.7-static-devel~0.9.7g~2.11.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.7g~2.11.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.7", rpm:"lib64openssl0.9.7~0.9.7g~2.11.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.7-devel", rpm:"lib64openssl0.9.7-devel~0.9.7g~2.11.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.7-static-devel", rpm:"lib64openssl0.9.7-static-devel~0.9.7g~2.11.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8", rpm:"libopenssl0.9.8~0.9.8h~3.5mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8-devel", rpm:"libopenssl0.9.8-devel~0.9.8h~3.5mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.8-static-devel", rpm:"libopenssl0.9.8-static-devel~0.9.8h~3.5mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8h~3.5mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8", rpm:"lib64openssl0.9.8~0.9.8h~3.5mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-devel", rpm:"lib64openssl0.9.8-devel~0.9.8h~3.5mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-static-devel", rpm:"lib64openssl0.9.8-static-devel~0.9.8h~3.5mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.7", rpm:"libopenssl0.9.7~0.9.7c~3.12.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.7-devel", rpm:"libopenssl0.9.7-devel~0.9.7c~3.12.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0.9.7-static-devel", rpm:"libopenssl0.9.7-static-devel~0.9.7c~3.12.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.7c~3.12.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
