# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-11618 (libsndfile)
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
  script_oid("1.3.6.1.4.1.25623.1.0.66439");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_cve_id("CVE-2009-0186", "CVE-2009-1788", "CVE-2009-1791");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-11618 (libsndfile)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"Update Information:

Version 1.0.20 (2009-03-14)

  * Fix potential heap overflow in VOC file parser

Version 1.0.19 (2009-03-02)

  * Fix for CVE-2009-0186 (Alin Rad Pop, Secunia Research).

  * Huge number of minor bug fixes as a result of static analysis.
Version 1.0.18 (2009-02-07)

  * Add Ogg/Vorbis support (thanks to John ffitch).

  * Remove captive FLAC library.

  * Many new features and bug fixes.

ChangeLog:

  * Sat Nov 14 2009 Orcan Ogetbil  - 1.0.20-3

  - Add FLAC/Ogg/Vorbis support (BR: libvorbis-devel)

  - Make build verbose

  - Remove rpath

  - Fix ChangeLog encoding

  - Move the big Changelog to the devel package

  * Sat Jul 25 2009 Fedora Release Engineering  - 1.0.20-2


  * Sat Jun  6 2009 Lennart Poettering  - 1.0.20-1

  - Updated to 1.0.20");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update libsndfile' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-11618");
  script_tag(name:"summary", value:"The remote host is missing an update to libsndfile
announced via advisory FEDORA-2009-11618.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488361");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=502657");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=502658");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"libsndfile", rpm:"libsndfile~1.0.20~3.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsndfile-devel", rpm:"libsndfile-devel~1.0.20~3.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsndfile-debuginfo", rpm:"libsndfile-debuginfo~1.0.20~3.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
