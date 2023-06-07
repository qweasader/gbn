# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-8826 (pidgin)
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
  script_oid("1.3.6.1.4.1.25623.1.0.64723");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-2694");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-8826 (pidgin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

2.6.1 fixes an issue where pidgin can crash if you are sent a certain type of
URL over Yahoo.

ChangeLog:

  * Wed Aug 19 2009 Warren Togami  2.6.1-1

  - 2.6.1: Fix a crash when some users send you a link in a Yahoo IM

  * Tue Aug 18 2009 Warren Togami  2.6.0-1

  - CVE-2009-2694

  - Voice and Video support via farsight2 (Fedora 11+)

  - Numerous other bug fixes

  * Thu Aug  6 2009 Warren Togami  2.6.0-0.11.20090812

  - new snapshot at the request of maiku

  * Thu Aug  6 2009 Warren Togami  2.6.0-0.10.20090806

  - new snapshot - theoretically better sound quality in voice chat

  * Tue Aug  4 2009 Warren Togami  2.6.0-0.9.20090804

  - new snapshot");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update pidgin' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8826");
  script_tag(name:"summary", value:"The remote host is missing an update to pidgin
announced via advisory FEDORA-2009-8826.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.6.1~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"finch-devel", rpm:"finch-devel~2.6.1~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.6.1~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.6.1~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-perl", rpm:"libpurple-perl~2.6.1~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-tcl", rpm:"libpurple-tcl~2.6.1~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.6.1~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-devel", rpm:"pidgin-devel~2.6.1~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-docs", rpm:"pidgin-docs~2.6.1~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.6.1~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-debuginfo", rpm:"pidgin-debuginfo~2.6.1~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
