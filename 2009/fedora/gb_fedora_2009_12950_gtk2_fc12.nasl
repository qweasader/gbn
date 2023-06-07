# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-12950 (gtk2)
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
  script_oid("1.3.6.1.4.1.25623.1.0.66571");
  script_cve_id("CVE-2009-0318");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 12 FEDORA-2009-12950 (gtk2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC12");
  script_tag(name:"insight", value:"Update Information:

This update fixes a crash issue in gtk2 involving out of process
windows.  Side effects of the bug are sporadic panel crashes, and
occasional crashes in gnome-screensaver when typing an invalid
password.

This update also addresses a crash in Inkscape when using the text tool.

ChangeLog:

  * Tue Dec  8 2009 Matthias Clasen  - 2.18.5-1

  - Update to 2.18.5

  * Tue Dec  1 2009 Matthias Clasen  - 2.18.4-3

  - Fix a mistranslated format string in no_NO (#500067)

  * Tue Dec  1 2009 Matthias Clasen  - 2.18.4-2

  - Make compose sequences for  consistent (#510741)

  * Tue Dec  1 2009 Matthias Clasen  - 2.18.4-1

  - Update to 2.18.4");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update gtk2' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-12950");
  script_tag(name:"summary", value:"The remote host is missing an update to gtk2
announced via advisory FEDORA-2009-12950.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=540308");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=538156");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=544590");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"gtk2", rpm:"gtk2~2.18.5~3.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gtk2-devel", rpm:"gtk2-devel~2.18.5~3.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gtk2-devel-docs", rpm:"gtk2-devel-docs~2.18.5~3.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gtk2-immodule-xim", rpm:"gtk2-immodule-xim~2.18.5~3.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gtk2-immodules", rpm:"gtk2-immodules~2.18.5~3.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gtk2-debuginfo", rpm:"gtk2-debuginfo~2.18.5~3.fc12", rls:"FC12")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
