# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:020 (xine-lib)
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
  script_oid("1.3.6.1.4.1.25623.1.0.63252");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-01-26 18:18:20 +0100 (Mon, 26 Jan 2009)");
  script_cve_id("CVE-2008-3231", "CVE-2008-5233", "CVE-2008-5234", "CVE-2008-5236", "CVE-2008-5237", "CVE-2008-5239", "CVE-2008-5240", "CVE-2008-5241", "CVE-2008-5243", "CVE-2008-5245", "CVE-2008-5246");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:020 (xine-lib)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0)");
  script_tag(name:"insight", value:"For details, please visit the referenced security advisories.

This update provides the fix for all these security issues found in
xine-lib 1.1.11 of Mandriva 2008.1. The vulnerabilities: CVE-2008-5234,
CVE-2008-5236, CVE-2008-5237, CVE-2008-5239, CVE-2008-5240,
CVE-2008-5243 are found in xine-lib 1.1.15 of Mandriva 2009.0 and
are also fixed by this update.

Affected: 2008.1, 2009.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:020");
  script_tag(name:"summary", value:"The remote host is missing an update to xine-lib
announced via advisory MDVSA-2009:020.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libxine1", rpm:"libxine1~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxine-devel", rpm:"libxine-devel~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-aa", rpm:"xine-aa~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-caca", rpm:"xine-caca~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-dxr3", rpm:"xine-dxr3~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-esd", rpm:"xine-esd~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-flac", rpm:"xine-flac~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-gnomevfs", rpm:"xine-gnomevfs~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-image", rpm:"xine-image~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-jack", rpm:"xine-jack~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-plugins", rpm:"xine-plugins~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-pulse", rpm:"xine-pulse~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-sdl", rpm:"xine-sdl~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-smb", rpm:"xine-smb~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-wavpack", rpm:"xine-wavpack~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xine1", rpm:"lib64xine1~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xine-devel", rpm:"lib64xine-devel~1.1.11.1~4.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxine1", rpm:"libxine1~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxine-devel", rpm:"libxine-devel~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-aa", rpm:"xine-aa~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-caca", rpm:"xine-caca~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-dxr3", rpm:"xine-dxr3~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-esd", rpm:"xine-esd~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-flac", rpm:"xine-flac~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-gnomevfs", rpm:"xine-gnomevfs~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-image", rpm:"xine-image~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-jack", rpm:"xine-jack~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-plugins", rpm:"xine-plugins~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-pulse", rpm:"xine-pulse~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-sdl", rpm:"xine-sdl~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-smb", rpm:"xine-smb~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-wavpack", rpm:"xine-wavpack~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xine1", rpm:"lib64xine1~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xine-devel", rpm:"lib64xine-devel~1.1.15~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
