# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-7614 (seamonkey)
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
  script_oid("1.3.6.1.4.1.25623.1.0.64400");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-2210", "CVE-2009-1841", "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-1835", "CVE-2009-1832", "CVE-2009-1311", "CVE-2009-1307");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-7614 (seamonkey)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"Update Information:

Update to upstream version 1.1.17, fixing multiple security flaws.

ChangeLog:

  * Fri Jul 10 2009 Martin Stransky  1.1.17-1

  - Update to 1.1.17

  * Thu Jun 18 2009 Kai Engert  1.1.16-1.11.1

  - fix categories in desktop files

  * Thu May  7 2009 Kai Engert  1.1.16-1

  - Update to 1.1.16

  * Wed May  6 2009 Martin Stransky  1.1.15-4

  - build with -fno-strict-aliasing (#468415)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update seamonkey' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-7614");
  script_tag(name:"summary", value:"The remote host is missing an update to seamonkey
announced via advisory FEDORA-2009-7614.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=507812");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503583");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503578");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503580");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503576");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503569");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496271");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496263");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.1.17~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~1.1.17~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
