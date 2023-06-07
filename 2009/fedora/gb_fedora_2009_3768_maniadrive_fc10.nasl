# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-3768 (maniadrive)
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
  script_oid("1.3.6.1.4.1.25623.1.0.64099");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
  script_cve_id("CVE-2008-5557", "CVE-2008-5658", "CVE-2008-3658", "CVE-2008-5498", "CVE-2008-5814", "CVE-2009-0754", "CVE-2009-1271", "CVE-2008-2829", "CVE-2008-3660");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-3768 (maniadrive)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

Update to PHP 5.2.9

ChangeLog:

  * Thu Apr 16 2009 Remi Collet  - 1.2-13

  - Rebuild for php 5.2.9");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update maniadrive' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3768");
  script_tag(name:"summary", value:"The remote host is missing an update to maniadrive
announced via advisory FEDORA-2009-3768.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=478425");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=494530");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=459529");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=459572");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=452808");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=474824");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=478848");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=479272");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"maniadrive", rpm:"maniadrive~1.2~13.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"maniadrive-track-editor", rpm:"maniadrive-track-editor~1.2~13.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"raydium", rpm:"raydium~1.2~13.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"raydium-devel", rpm:"raydium-devel~1.2~13.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"maniadrive-debuginfo", rpm:"maniadrive-debuginfo~1.2~13.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
