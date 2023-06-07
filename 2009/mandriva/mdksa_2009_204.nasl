# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:204 (wxgtk)
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
  script_oid("1.3.6.1.4.1.25623.1.0.64676");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-2369");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:204 (wxgtk)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|2009\.1|4\.0|mes5)");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in wxgtk:

Integer overflow in the wxImage::Create function in
src/common/image.cpp in wxWidgets 2.8.10 allows attackers to cause
a denial of service (crash) and possibly execute arbitrary code via
a crafted JPEG file, which triggers a heap-based buffer overflow.
NOTE: the provenance of this information is unknown. The details are
obtained solely from third party information (CVE-2009-2369).

This update provides a solution to this vulnerability.

Affected: 2008.1, 2009.0, 2009.1, Corporate 4.0, Enterprise Server 5.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:204");
  script_tag(name:"summary", value:"The remote host is missing an update to wxgtk
announced via advisory MDVSA-2009:204.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libwxgtk2.6", rpm:"libwxgtk2.6~2.6.4~14.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtk2.6-devel", rpm:"libwxgtk2.6-devel~2.6.4~14.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtk2.8", rpm:"libwxgtk2.8~2.8.7~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtk2.8-devel", rpm:"libwxgtk2.8-devel~2.8.7~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtkgl2.6", rpm:"libwxgtkgl2.6~2.6.4~14.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtkgl2.8", rpm:"libwxgtkgl2.8~2.8.7~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtkglu2.6", rpm:"libwxgtkglu2.6~2.6.4~14.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtkglu2.8", rpm:"libwxgtkglu2.8~2.8.7~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtku2.6", rpm:"libwxgtku2.6~2.6.4~14.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtku2.6-devel", rpm:"libwxgtku2.6-devel~2.6.4~14.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtku2.8", rpm:"libwxgtku2.8~2.8.7~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtku2.8-devel", rpm:"libwxgtku2.8-devel~2.8.7~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wxGTK2.6", rpm:"wxGTK2.6~2.6.4~14.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wxgtk2.8", rpm:"wxgtk2.8~2.8.7~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtk2.6", rpm:"lib64wxgtk2.6~2.6.4~14.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtk2.6-devel", rpm:"lib64wxgtk2.6-devel~2.6.4~14.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtk2.8", rpm:"lib64wxgtk2.8~2.8.7~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtk2.8-devel", rpm:"lib64wxgtk2.8-devel~2.8.7~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtkgl2.6", rpm:"lib64wxgtkgl2.6~2.6.4~14.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtkgl2.8", rpm:"lib64wxgtkgl2.8~2.8.7~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtkglu2.6", rpm:"lib64wxgtkglu2.6~2.6.4~14.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtkglu2.8", rpm:"lib64wxgtkglu2.8~2.8.7~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtku2.6", rpm:"lib64wxgtku2.6~2.6.4~14.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtku2.6-devel", rpm:"lib64wxgtku2.6-devel~2.6.4~14.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtku2.8", rpm:"lib64wxgtku2.8~2.8.7~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtku2.8-devel", rpm:"lib64wxgtku2.8-devel~2.8.7~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtk2.6", rpm:"libwxgtk2.6~2.6.4~16.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtk2.6-devel", rpm:"libwxgtk2.6-devel~2.6.4~16.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtk2.8", rpm:"libwxgtk2.8~2.8.8~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtk2.8-devel", rpm:"libwxgtk2.8-devel~2.8.8~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtkgl2.6", rpm:"libwxgtkgl2.6~2.6.4~16.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtkgl2.8", rpm:"libwxgtkgl2.8~2.8.8~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtkglu2.6", rpm:"libwxgtkglu2.6~2.6.4~16.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtkglu2.8", rpm:"libwxgtkglu2.8~2.8.8~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtku2.6", rpm:"libwxgtku2.6~2.6.4~16.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtku2.6-devel", rpm:"libwxgtku2.6-devel~2.6.4~16.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtku2.8", rpm:"libwxgtku2.8~2.8.8~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtku2.8-devel", rpm:"libwxgtku2.8-devel~2.8.8~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wxGTK2.6", rpm:"wxGTK2.6~2.6.4~16.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wxgtk2.8", rpm:"wxgtk2.8~2.8.8~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtk2.6", rpm:"lib64wxgtk2.6~2.6.4~16.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtk2.6-devel", rpm:"lib64wxgtk2.6-devel~2.6.4~16.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtk2.8", rpm:"lib64wxgtk2.8~2.8.8~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtk2.8-devel", rpm:"lib64wxgtk2.8-devel~2.8.8~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtkgl2.6", rpm:"lib64wxgtkgl2.6~2.6.4~16.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtkgl2.8", rpm:"lib64wxgtkgl2.8~2.8.8~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtkglu2.6", rpm:"lib64wxgtkglu2.6~2.6.4~16.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtkglu2.8", rpm:"lib64wxgtkglu2.8~2.8.8~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtku2.6", rpm:"lib64wxgtku2.6~2.6.4~16.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtku2.6-devel", rpm:"lib64wxgtku2.6-devel~2.6.4~16.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtku2.8", rpm:"lib64wxgtku2.8~2.8.8~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtku2.8-devel", rpm:"lib64wxgtku2.8-devel~2.8.8~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtk2.8", rpm:"libwxgtk2.8~2.8.9~3.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtk2.8-devel", rpm:"libwxgtk2.8-devel~2.8.9~3.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtkgl2.8", rpm:"libwxgtkgl2.8~2.8.9~3.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtkglu2.8", rpm:"libwxgtkglu2.8~2.8.9~3.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtku2.8", rpm:"libwxgtku2.8~2.8.9~3.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtku2.8-devel", rpm:"libwxgtku2.8-devel~2.8.9~3.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wxgtk2.8", rpm:"wxgtk2.8~2.8.9~3.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtk2.8", rpm:"lib64wxgtk2.8~2.8.9~3.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtk2.8-devel", rpm:"lib64wxgtk2.8-devel~2.8.9~3.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtkgl2.8", rpm:"lib64wxgtkgl2.8~2.8.9~3.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtkglu2.8", rpm:"lib64wxgtkglu2.8~2.8.9~3.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtku2.8", rpm:"lib64wxgtku2.8~2.8.9~3.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtku2.8-devel", rpm:"lib64wxgtku2.8-devel~2.8.9~3.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtk2.6", rpm:"libwxgtk2.6~2.6.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtk2.6-devel", rpm:"libwxgtk2.6-devel~2.6.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtkgl2.6", rpm:"libwxgtkgl2.6~2.6.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtkglu2.6", rpm:"libwxgtkglu2.6~2.6.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtku2.6", rpm:"libwxgtku2.6~2.6.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtku2.6-devel", rpm:"libwxgtku2.6-devel~2.6.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wxGTK2.6", rpm:"wxGTK2.6~2.6.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtk2.6", rpm:"lib64wxgtk2.6~2.6.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtk2.6-devel", rpm:"lib64wxgtk2.6-devel~2.6.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtkgl2.6", rpm:"lib64wxgtkgl2.6~2.6.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtkglu2.6", rpm:"lib64wxgtkglu2.6~2.6.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtku2.6", rpm:"lib64wxgtku2.6~2.6.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtku2.6-devel", rpm:"lib64wxgtku2.6-devel~2.6.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtk2.8", rpm:"libwxgtk2.8~2.8.8~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtk2.8-devel", rpm:"libwxgtk2.8-devel~2.8.8~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtkgl2.8", rpm:"libwxgtkgl2.8~2.8.8~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtkglu2.8", rpm:"libwxgtkglu2.8~2.8.8~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtku2.8", rpm:"libwxgtku2.8~2.8.8~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwxgtku2.8-devel", rpm:"libwxgtku2.8-devel~2.8.8~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wxgtk2.8", rpm:"wxgtk2.8~2.8.8~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtk2.8", rpm:"lib64wxgtk2.8~2.8.8~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtk2.8-devel", rpm:"lib64wxgtk2.8-devel~2.8.8~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtkgl2.8", rpm:"lib64wxgtkgl2.8~2.8.8~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtkglu2.8", rpm:"lib64wxgtkglu2.8~2.8.8~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtku2.8", rpm:"lib64wxgtku2.8~2.8.8~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wxgtku2.8-devel", rpm:"lib64wxgtku2.8-devel~2.8.8~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
