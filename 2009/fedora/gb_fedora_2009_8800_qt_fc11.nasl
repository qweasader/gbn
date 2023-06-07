# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-8800 (qt)
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
  script_oid("1.3.6.1.4.1.25623.1.0.64716");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-1725");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-8800 (qt)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"Update Information:

Qt's WebKit code did not properly handle numeric character
references, which could allow remote attackers to cause a
denial of service (memory corruption and application crash)
via a crafted HTML document.

Also included is:

  * a fix for lib symlinks changing erroneously on upgrades

  * a fix for Copy and paste issues

  * added support for more x keycodes

ChangeLog:

  * Tue Aug 18 2009 Than Ngo  - 4.5.2-2

  - security fix for CVE-2009-1725

  * Tue Aug 18 2009 Rex Dieter  4.5.2-1.2

  - kde-qt: 287-qmenu-respect-minwidth

  - kde-qt: 0288-more-x-keycodes (#475247)

  * Wed Aug  5 2009 Rex Dieter  4.5.2-1.1

  - use linker scripts for _debug targets (#510246)

  - apply upstream patch to fix issue in Copy and paste

  - optimize (icon-mostly) scriptlets

  - -x11: Requires(post, postun): /sbin/ldconfig");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update qt' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8800");
  script_tag(name:"summary", value:"The remote host is missing an update to qt
announced via advisory FEDORA-2009-8800.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=513813");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"qt", rpm:"qt~4.5.2~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-demos", rpm:"qt-demos~4.5.2~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-devel", rpm:"qt-devel~4.5.2~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-examples", rpm:"qt-examples~4.5.2~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-mysql", rpm:"qt-mysql~4.5.2~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-odbc", rpm:"qt-odbc~4.5.2~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-postgresql", rpm:"qt-postgresql~4.5.2~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-x11", rpm:"qt-x11~4.5.2~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-debuginfo", rpm:"qt-debuginfo~4.5.2~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-doc", rpm:"qt-doc~4.5.2~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
