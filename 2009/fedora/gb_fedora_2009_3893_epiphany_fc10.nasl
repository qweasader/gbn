# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-3893 (epiphany)
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
  script_oid("1.3.6.1.4.1.25623.1.0.63883");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-04-28 20:40:12 +0200 (Tue, 28 Apr 2009)");
  script_cve_id("CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-0652", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1310", "CVE-2009-1311", "CVE-2009-1312");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-3893 (epiphany)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"ChangeLog:

  * Tue Apr 21 2009 Christopher Aillon  - 2.24.3-5

  - Rebuild against newer gecko

  * Fri Mar 27 2009 Christopher Aillon  - 2.24.3-4

  - Rebuild against newer gecko");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update epiphany' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3893");
  script_tag(name:"summary", value:"The remote host is missing an update to epiphany
announced via advisory FEDORA-2009-3893.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496252");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496253");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496255");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496256");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=486704");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496262");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496263");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496266");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496267");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496270");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496271");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496274");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"epiphany", rpm:"epiphany~2.24.3~5.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany-devel", rpm:"epiphany-devel~2.24.3~5.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany-debuginfo", rpm:"epiphany-debuginfo~2.24.3~5.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
