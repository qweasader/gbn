# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-1399 (xulrunner)
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
  script_oid("1.3.6.1.4.1.25623.1.0.63379");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_cve_id("CVE-2009-0353", "CVE-2009-0355", "CVE-2009-0357", "CVE-2009-0352", "CVE-2009-0354", "CVE-2009-0356", "CVE-2009-0358");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-1399 (xulrunner)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC9");
  script_tag(name:"insight", value:"XULRunner provides the XUL Runtime environment for Gecko applications.

Update Information:

Update to the new upstream Firefox 3.0.6 / XULRunner 1.9.0.6
fixing multiple security issues.

This update also contains new builds of all applications
depending on Gecko libraries, built against the new version.

ChangeLog:

  * Wed Feb  4 2009 Christopher Aillon  1.9.0.6-1

  - Update to 1.9.0.6

  * Tue Dec 16 2008 Christopher Aillon  1.9.0.5-1

  - Update to 1.9.0.5

  * Wed Nov 12 2008 Christopher Aillon  1.9.0.4-1

  - Update to 1.9.0.4");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update xulrunner' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1399");
  script_tag(name:"summary", value:"The remote host is missing an update to xulrunner
announced via advisory FEDORA-2009-1399.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483141");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483143");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483145");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483139");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483142");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483144");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483150");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~1.9.0.6~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~1.9.0.6~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xulrunner-devel-unstable", rpm:"xulrunner-devel-unstable~1.9.0.6~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xulrunner-debuginfo", rpm:"xulrunner-debuginfo~1.9.0.6~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
