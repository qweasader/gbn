# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-3101 (seamonkey)
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
  script_oid("1.3.6.1.4.1.25623.1.0.63723");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-04-06 20:58:11 +0200 (Mon, 06 Apr 2009)");
  script_cve_id("CVE-2009-1044", "CVE-2009-1169", "CVE-2009-0776", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0357", "CVE-2009-0352", "CVE-2009-0353");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-3101 (seamonkey)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC9");
  script_tag(name:"insight", value:"SeaMonkey is an all-in-one Internet application suite. It includes
a browser, mail/news client, IRC client, JavaScript debugger, and
a tool to inspect the DOM for web pages. It is derived from the
application formerly known as Mozilla Application Suite.

ChangeLog:

  * Fri Mar 27 2009 Christopher Aillon  - 1.15.1-3

  - Add patches for MFSA-2009-12, MFSA-2009-13

  * Wed Mar 25 2009 Christopher Aillon  - 1.15.1-2

  - Update default homepage");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update seamonkey' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3101");
  script_tag(name:"summary", value:"The remote host is missing an update to seamonkey
announced via advisory FEDORA-2009-3101.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=492212");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=492211");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488290");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488272");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488273");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488276");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488283");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483145");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483139");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483141");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.1.15~3.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~1.1.15~3.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
