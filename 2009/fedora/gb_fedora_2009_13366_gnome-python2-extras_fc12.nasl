# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-13366 (gnome-python2-extras)
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
  script_oid("1.3.6.1.4.1.25623.1.0.66568");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_cve_id("CVE-2009-3979", "CVE-2009-3980", "CVE-2009-3982", "CVE-2009-3983", "CVE-2009-3984", "CVE-2009-3985", "CVE-2009-3986", "CVE-2009-3388", "CVE-2009-3389");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 12 FEDORA-2009-13366 (gnome-python2-extras)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC12");
  script_tag(name:"insight", value:"Update Information:

Update to new upstream Firefox version 3.5.6, fixing multiple security issues.

Update also includes all packages depending on gecko-libs rebuilt against
new version of Firefox / XULRunner.

ChangeLog:

  * Wed Dec 16 2009 Jan Horak  - 2.25.3-14

  - Rebuild against newer gecko");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update gnome-python2-extras' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-13366");
  script_tag(name:"summary", value:"The remote host is missing an update to gnome-python2-extras
announced via advisory FEDORA-2009-13366.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=546694");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=546720");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=546722");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=546726");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=546724");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"gnome-python2-extras", rpm:"gnome-python2-extras~2.25.3~14.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python2-gda", rpm:"gnome-python2-gda~2.25.3~14.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python2-gda", rpm:"gnome-python2-gda~devel~2.25.3", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python2-gdl", rpm:"gnome-python2-gdl~2.25.3~14.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python2-gtkhtml2", rpm:"gnome-python2-gtkhtml2~2.25.3~14.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python2-gtkmozembed", rpm:"gnome-python2-gtkmozembed~2.25.3~14.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python2-gtkspell", rpm:"gnome-python2-gtkspell~2.25.3~14.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python2-libegg", rpm:"gnome-python2-libegg~2.25.3~14.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python2-extras", rpm:"gnome-python2-extras~debuginfo~2.25.3", rls:"FC12")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
