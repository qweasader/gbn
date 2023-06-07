# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:085 (gstreamer0.10-plugins-base)
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
  script_oid("1.3.6.1.4.1.25623.1.0.63718");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-04-06 20:58:11 +0200 (Mon, 06 Apr 2009)");
  script_cve_id("CVE-2008-4316", "CVE-2009-0586");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:085 (gstreamer0.10-plugins-base)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.0|2008\.1|2009\.0)");
  script_tag(name:"insight", value:"Integer overflows in gstreamer0.10-plugins-base Base64 encoding and
decoding functions (related with glib2.0 issue CVE-2008-4316) may
lead attackers to cause denial of service. Although vector attacks
are not known yet (CVE-2009-0586).

This update provide the fix for that security issue.

Affected: 2008.0, 2008.1, 2009.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:085");
  script_tag(name:"summary", value:"The remote host is missing an update to gstreamer0.10-plugins-base
announced via advisory MDVSA-2009:085.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"gstreamer0.10-cdparanoia", rpm:"gstreamer0.10-cdparanoia~0.10.14~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-gnomevfs", rpm:"gstreamer0.10-gnomevfs~0.10.14~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-libvisual", rpm:"gstreamer0.10-libvisual~0.10.14~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-plugins-base", rpm:"gstreamer0.10-plugins-base~0.10.14~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgstreamer-plugins-base0.10", rpm:"libgstreamer-plugins-base0.10~0.10.14~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgstreamer-plugins-base0.10-devel", rpm:"libgstreamer-plugins-base0.10-devel~0.10.14~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gstreamer-plugins-base0.10", rpm:"lib64gstreamer-plugins-base0.10~0.10.14~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gstreamer-plugins-base0.10-devel", rpm:"lib64gstreamer-plugins-base0.10-devel~0.10.14~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-cdparanoia", rpm:"gstreamer0.10-cdparanoia~0.10.17~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-gnomevfs", rpm:"gstreamer0.10-gnomevfs~0.10.17~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-libvisual", rpm:"gstreamer0.10-libvisual~0.10.17~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-plugins-base", rpm:"gstreamer0.10-plugins-base~0.10.17~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgstreamer-plugins-base0.10", rpm:"libgstreamer-plugins-base0.10~0.10.17~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgstreamer-plugins-base0.10-devel", rpm:"libgstreamer-plugins-base0.10-devel~0.10.17~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gstreamer-plugins-base0.10", rpm:"lib64gstreamer-plugins-base0.10~0.10.17~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gstreamer-plugins-base0.10-devel", rpm:"lib64gstreamer-plugins-base0.10-devel~0.10.17~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-cdparanoia", rpm:"gstreamer0.10-cdparanoia~0.10.20~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-gnomevfs", rpm:"gstreamer0.10-gnomevfs~0.10.20~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-libvisual", rpm:"gstreamer0.10-libvisual~0.10.20~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-plugins-base", rpm:"gstreamer0.10-plugins-base~0.10.20~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgstreamer-plugins-base0.10", rpm:"libgstreamer-plugins-base0.10~0.10.20~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgstreamer-plugins-base0.10-devel", rpm:"libgstreamer-plugins-base0.10-devel~0.10.20~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gstreamer-plugins-base0.10", rpm:"lib64gstreamer-plugins-base0.10~0.10.20~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gstreamer-plugins-base0.10-devel", rpm:"lib64gstreamer-plugins-base0.10-devel~0.10.20~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
