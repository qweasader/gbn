# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-0542 (xine-lib)
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
  script_oid("1.3.6.1.4.1.25623.1.0.63213");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
  script_cve_id("CVE-2008-5234", "CVE-2008-5236", "CVE-2008-5237", "CVE-2008-5239", "CVE-2008-5240", "CVE-2008-5243", "CVE-2008-3231");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-0542 (xine-lib)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC9");
  script_tag(name:"insight", value:"Update Information:

This updates xine-lib to the upstream 1.1.16 release.
This fixes several bugs, including the security issues
CVE-2008-5234 vector 1, CVE-2008-5236, CVE-2008-5237,
CVE-2008-5239, CVE-2008-5240 vectors 3 & 4 and CVE-2008-5243.

In addition, the Fedora xine-lib package now
includes the demuxers for the MPEG container format,
which are not patent-encumbered. (The decoders for actual
MPEG video and audio data are still excluded due to
software patents.)

ChangeLog:

  * Wed Jan  7 2009 Kevin Kofler  - 1.1.16-1.1

  - patch for old libcaca in F9-

  * Wed Jan  7 2009 Rex Dieter  - 1.1.16-1

  - xine-lib-1.1.16, plugin ABI 1.25

  - --with-external-libdvdnav, include mpeg demuxers (#213597)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update xine-lib' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-0542");
  script_tag(name:"summary", value:"The remote host is missing an update to xine-lib
announced via advisory FEDORA-2009-0542.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=213597");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"xine-lib", rpm:"xine-lib~1.1.16~1.fc9.1", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-lib-devel", rpm:"xine-lib-devel~1.1.16~1.fc9.1", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-lib-extras", rpm:"xine-lib-extras~1.1.16~1.fc9.1", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-lib-pulseaudio", rpm:"xine-lib-pulseaudio~1.1.16~1.fc9.1", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-lib-debuginfo", rpm:"xine-lib-debuginfo~1.1.16~1.fc9.1", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
