# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-8329 (java-1.6.0-openjdk)
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
  script_oid("1.3.6.1.4.1.25623.1.0.64613");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2009-0217", "CVE-2009-2475", "CVE-2009-2476", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2689", "CVE-2009-2690", "CVE-2009-1896");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-8329 (java-1.6.0-openjdk)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"Update Information:

Urgent security updates have been included

ChangeLog:

  * Tue Aug  4 2009 Lillian Angel  - 1:1.6.0-27.b16

  - Updated java-1.6.0-openjdk-netx.patch, and renamed to
java-1.6.0-openjdk-netxandplugin.patch.

  - Added java-1.6.0-openjdk-securitypatches.patch.

  - Resolves: rhbz#512101 rhbz#512896 rhbz#512914 rhbz#512907 rhbz#512921
              rhbz#511915 rhbz#512915 rhbz#512920 rhbz#512714 rhbz#513215
              rhbz#513220 rhbz#513222 rhbz#513223 rhbz#503794

  * Mon Aug  3 2009 Christopher Aillon  - 1:1.6.0.0-26.b16

  - Rebuild against newer gecko

  * Fri Jul 17 2009 Jan Horak  - 1:1.6.0.0-25.b16

  - Rebuild against newer gecko");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update java-1.6.0-openjdk' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8329");
  script_tag(name:"summary", value:"The remote host is missing an update to java-1.6.0-openjdk
announced via advisory FEDORA-2009-8329.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=511915");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=513215");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=513220");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512921");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512896");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512907");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512914");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512915");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512920");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=513222");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=513223");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512101");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~27.b16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~demo~1.6.0.0", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~devel~1.6.0.0", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~javadoc~1.6.0.0", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~plugin~1.6.0.0", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~src~1.6.0.0", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~debuginfo~1.6.0.0", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
