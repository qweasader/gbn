# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-1213 (gstreamer-plugins-good)
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
  script_oid("1.3.6.1.4.1.25623.1.0.63455");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-03-02 19:11:09 +0100 (Mon, 02 Mar 2009)");
  script_cve_id("CVE-2009-0386", "CVE-2009-0387");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-1213 (gstreamer-plugins-good)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"ChangeLog:

  * Mon Jan 26 2009 - Bastien Nocera  - 0.10.13-1

  - Update to 0.10.13

  - Update libv4l patch

  * Wed Jan 14 2009 Warren Togami  0.10.11-4

  - Bug #477877 Fix multilib conflict in -devel

  - Bug #478449 Fix ladspa on lib64

  * Wed Jan 14 2009 Lennart Poettering  0.10.11-3

  - Bug #470000 Fix thread/memleak due to ref-loop

  * Tue Jan 13 2009 Bastien Nocera  - 0.10.11-2

  - Avoid pulsesink hang when PulseAudio disappears");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update gstreamer-plugins-good' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1213");
  script_tag(name:"summary", value:"The remote host is missing an update to gstreamer-plugins-good
announced via advisory FEDORA-2009-1213.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=481267");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483736");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483737");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"gstreamer-plugins-good", rpm:"gstreamer-plugins-good~0.10.13~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-plugins-good", rpm:"gstreamer-plugins-good~devel~0.10.13", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-plugins-good", rpm:"gstreamer-plugins-good~debuginfo~0.10.13", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
