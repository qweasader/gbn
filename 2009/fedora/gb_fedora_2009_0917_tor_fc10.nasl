# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-0917 (tor)
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
  script_oid("1.3.6.1.4.1.25623.1.0.63270");
  script_version("2022-05-13T11:28:10+0000");
  script_cve_id("CVE-2009-0414");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2009-01-26 18:18:20 +0100 (Mon, 26 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-0917 (tor)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

New upstream release 0.2.0.33, with lots of bug fixes and one security fix.

ChangeLog:

  * Thu Jan 22 2009 Enrico Scholz  - 0.2.0.33-1

  - updated to 0.2.0.33 (SECURITY: fixed heap-corruption bug)

  * Sun Dec  7 2008 Enrico Scholz  - 0.2.0.32-1

  - updated to 0.2.0.32

  - removed -setgroups patch, supplementary groups are now set upstream");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update tor' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-0917");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33399");
  script_tag(name:"summary", value:"The remote host is missing an update to tor
announced via advisory FEDORA-2009-0917.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=481289");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"tor", rpm:"tor~0.2.0.33~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tor-core", rpm:"tor-core~0.2.0.33~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tor-lsb", rpm:"tor-lsb~0.2.0.33~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tor-debuginfo", rpm:"tor-debuginfo~0.2.0.33~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
