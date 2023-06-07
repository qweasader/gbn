# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-8317 (firebird)
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
  script_oid("1.3.6.1.4.1.25623.1.0.64739");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-2620");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 10 FEDORA-2009-8317 (firebird)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

Upgrade from previous package version may be a problem  since previous
version remove /var/run/firebird and it shouldn't.
This release fix this problem for future updates  If you are in that
case (no longer /var/run/firebird directory after upgrade), just
reinstall firebird-2.1.3.18185.0-2 package or create
/var/run/firebird owned by user firebird

ChangeLog:

  * Wed Aug  5 2009 Philippe Makowski  2.1.3.18185.0-2

  - rename /usr/bin/gstat to /usr/bin/gstat-fb  to avoid conflict with ganglia-gmond (rh #515510)

  - remove stupid rm -rf in postun

  * Thu Jul 30 2009 Philippe Makowski  2.1.3.18185.0-1

  - Update to 2.1.3.18185

  - Fix rh #514463

  - Remove doc patch

  - Apply backport initscript patch");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update firebird' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8317");
  script_tag(name:"summary", value:"The remote host is missing an update to firebird
announced via advisory FEDORA-2009-8317.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=514463");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"firebird", rpm:"firebird~2.1.3.18185.0~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-classic", rpm:"firebird-classic~2.1.3.18185.0~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-devel", rpm:"firebird-devel~2.1.3.18185.0~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-doc", rpm:"firebird-doc~2.1.3.18185.0~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-filesystem", rpm:"firebird-filesystem~2.1.3.18185.0~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-libfbclient", rpm:"firebird-libfbclient~2.1.3.18185.0~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-libfbembed", rpm:"firebird-libfbembed~2.1.3.18185.0~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-superserver", rpm:"firebird-superserver~2.1.3.18185.0~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-debuginfo", rpm:"firebird-debuginfo~2.1.3.18185.0~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
