# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-2884 (thunderbird)
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
  script_oid("1.3.6.1.4.1.25623.1.0.63657");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
  script_cve_id("CVE-2009-0040", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0772", "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0355", "CVE-2009-0776");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-2884 (thunderbird)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC9");
  script_tag(name:"insight", value:"Update Information:

Several flaws were found in the processing of malformed HTML mail content. An
HTML mail message containing malicious content could cause Thunderbird to crash
or, potentially, execute arbitrary code as the user running Thunderbird.
(CVE-2009-0040, CVE-2009-0352, CVE-2009-0353, CVE-2009-0772, CVE-2009-0774,
CVE-2009-0775)    Several flaws were found in the way malformed content was
processed. An HTML mail message containing specially-crafted content could
potentially trick a Thunderbird user into surrendering sensitive information.
(CVE-2009-0355, CVE-2009-0776)    Note: JavaScript support is disabled by
default in Thunderbird. None of the above issues are exploitable unless
JavaScript is enabled.

ChangeLog:

  * Fri Mar 20 2009 Christopher Aillon  - 2.0.0.21-1

  - Update to 2.0.0.21");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update thunderbird' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2884");
  script_tag(name:"summary", value:"The remote host is missing an update to thunderbird
announced via advisory FEDORA-2009-2884.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=486355");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483139");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483141");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483143");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488273");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488283");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488287");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488290");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"<td>thunderbird", rpm:"<td>thunderbird~2.0.0.21~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~2.0.0.21~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~2.0.0.21~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
