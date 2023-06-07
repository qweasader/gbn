# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory RHSA-2009:1463 ()
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
  script_oid("1.3.6.1.4.1.25623.1.0.64946");
  script_version("2022-01-21T08:36:19+0000");
  script_tag(name:"last_modification", value:"2022-01-21 08:36:19 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-09-28 19:09:13 +0200 (Mon, 28 Sep 2009)");
  script_cve_id("CVE-2009-2905");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Security Advisory RHSA-2009:1463");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(3|4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1463.

Newt is a programming library for color text mode, widget-based user
interfaces. Newt can be used to add stacked windows, entry widgets,
checkboxes, radio buttons, labels, plain text fields, scrollbars, and so
on, to text mode user interfaces.

A heap-based buffer overflow flaw was found in the way newt processes
content that is to be displayed in a text dialog box. A local attacker
could issue a specially-crafted text dialog box display request (direct or
via a custom application), leading to a denial of service (application
crash) or, potentially, arbitrary code execution with the privileges of the
user running the application using the newt library. (CVE-2009-2905)

Users of newt should upgrade to these updated packages, which contain a
backported patch to correct this issue. After installing the updated
packages, all applications using the newt library must be restarted for the
update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1463.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"newt", rpm:"newt~0.51.5~2.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"newt-debuginfo", rpm:"newt-debuginfo~0.51.5~2.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"newt-devel", rpm:"newt-devel~0.51.5~2.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"newt", rpm:"newt~0.51.6~10.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"newt-debuginfo", rpm:"newt-debuginfo~0.51.6~10.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"newt-devel", rpm:"newt-devel~0.51.6~10.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"newt", rpm:"newt~0.52.2~12.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"newt-debuginfo", rpm:"newt-debuginfo~0.52.2~12.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"newt-devel", rpm:"newt-devel~0.52.2~12.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
