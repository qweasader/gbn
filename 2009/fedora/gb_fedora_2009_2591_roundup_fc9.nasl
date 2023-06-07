# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-2591 (roundup)
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
  script_oid("1.3.6.1.4.1.25623.1.0.63533");
  script_version("2022-05-13T11:28:10+0000");
  script_cve_id("CVE-2009-2737");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2009-03-13 19:24:56 +0100 (Fri, 13 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_name("Fedora Core 9 FEDORA-2009-2591 (roundup)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC9");
  script_tag(name:"insight", value:"ChangeLog:

  * Mon Mar  9 2009 Paul P. Komkoff Jr  - 1.4.6-4

  - security bug bz#489355

  * Wed Feb 25 2009 Fedora Release Engineering  - 1.4.6-3

  * Sat Nov 29 2008 Ignacio Vazquez-Abrams  - 1.4.6-2

  - Rebuild for Python 2.6

  * Fri Oct  3 2008 Paul P. Komkoff Jr  - 1.4.6-1

  - new upstream version");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update roundup' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2591");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34059");
  script_tag(name:"summary", value:"The remote host is missing an update to roundup
announced via advisory FEDORA-2009-2591.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=489355");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"<td>roundup", rpm:"<td>roundup~1.4.6~4.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"roundup", rpm:"roundup~1.4.6~4.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
