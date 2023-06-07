# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-12813 (gcc)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66588");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_cve_id("CVE-2009-3736");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 12 FEDORA-2009-12813 (gcc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC12");
  script_tag(name:"insight", value:"ChangeLog:

  * Tue Dec 22 2009 Jakub Jelinek  4.4.2-20

  - fix MEM_SIZE of reload created stack slots (#548825,
PR rtl-optimization/42429)

  - fix addition of one character long filenames in fastjar (#549493)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update gcc' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-12813");
  script_tag(name:"summary", value:"The remote host is missing an update to gcc
announced via advisory FEDORA-2009-12813.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=537941");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"cpp", rpm:"cpp~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc", rpm:"gcc~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-c++", rpm:"gcc-c++~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-gfortran", rpm:"gcc-gfortran~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-gnat", rpm:"gcc-gnat~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-java", rpm:"gcc-java~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-objc", rpm:"gcc-objc~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-objc++", rpm:"gcc-objc++~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgcc", rpm:"libgcc~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgcj", rpm:"libgcj~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgcj-devel", rpm:"libgcj-devel~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgcj-src", rpm:"libgcj-src~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgfortran", rpm:"libgfortran~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnat", rpm:"libgnat~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnat-devel", rpm:"libgnat-devel~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgomp", rpm:"libgomp~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmudflap", rpm:"libmudflap~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmudflap-devel", rpm:"libmudflap-devel~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libobjc", rpm:"libobjc~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libstdc++", rpm:"libstdc++~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libstdc++-devel", rpm:"libstdc++-devel~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libstdc++-docs", rpm:"libstdc++-docs~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-debuginfo", rpm:"gcc-debuginfo~4.4.2~20.fc12", rls:"FC12")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
