# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory RHSA-2009:0018 ()
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63111");
  script_version("2022-01-21T08:36:19+0000");
  script_tag(name:"last_modification", value:"2022-01-21 08:36:19 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-01-07 23:16:01 +0100 (Wed, 07 Jan 2009)");
  script_cve_id("CVE-2008-2383");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:0018");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(3|4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0018.

The xterm program is a terminal emulator for the X Window System.

A flaw was found in the xterm handling of Device Control Request Status
String (DECRQSS) escape sequences. An attacker could create a malicious
text file (or log entry, if unfiltered) that could run arbitrary commands
if read by a victim inside an xterm window. (CVE-2008-2383)

All xterm users are advised to upgrade to the updated package, which
contains a backported patch to resolve this issue. All running instances of
xterm must be restarted for the update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0018.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#important");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"xterm", rpm:"xterm~179~11.EL3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xterm-debuginfo", rpm:"xterm-debuginfo~179~11.EL3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xterm", rpm:"xterm~192~8.el4_7.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xterm-debuginfo", rpm:"xterm-debuginfo~192~8.el4_7.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xterm", rpm:"xterm~215~5.el5_2.2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xterm-debuginfo", rpm:"xterm-debuginfo~215~5.el5_2.2", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
