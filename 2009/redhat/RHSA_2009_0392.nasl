# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory RHSA-2009:0392 ()
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
  script_oid("1.3.6.1.4.1.25623.1.0.63644");
  script_version("2022-01-21T08:36:19+0000");
  script_tag(name:"last_modification", value:"2022-01-21 08:36:19 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
  script_cve_id("CVE-2006-2426", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1102", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1105", "CVE-2009-1106", "CVE-2009-1107");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:0392");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0392.

The Sun 1.6.0 Java release includes the Sun Java 6 Runtime Environment and
the Sun Java 6 Software Development Kit.

This update fixes several vulnerabilities in the Sun Java 6 Runtime
Environment and the Sun Java 6 Software Development Kit. These
vulnerabilities are summarized on the Advance notification of Security
Updates for Java SE page from Sun Microsystems, listed in the References
section. (CVE-2006-2426, CVE-2009-1093, CVE-2009-1094, CVE-2009-1095,
CVE-2009-1096, CVE-2009-1097, CVE-2009-1098, CVE-2009-1099, CVE-2009-1100,
CVE-2009-1101, CVE-2009-1102, CVE-2009-1103, CVE-2009-1104, CVE-2009-1105,
CVE-2009-1106, CVE-2009-1107)

Users of java-1.6.0-sun should upgrade to these updated packages, which
correct these issues. All running instances of Sun Java must be restarted
for the update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0392.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#critical");
  script_xref(name:"URL", value:"http://blogs.sun.com/security/entry/advance_notification_of_security_updates4");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"java-1.6.0-sun", rpm:"java-1.6.0-sun~1.6.0.13~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-sun-demo", rpm:"java-1.6.0-sun-demo~1.6.0.13~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-sun-devel", rpm:"java-1.6.0-sun-devel~1.6.0.13~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-sun-jdbc", rpm:"java-1.6.0-sun-jdbc~1.6.0.13~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-sun-plugin", rpm:"java-1.6.0-sun-plugin~1.6.0.13~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-sun-src", rpm:"java-1.6.0-sun-src~1.6.0.13~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-sun", rpm:"java-1.6.0-sun~1.6.0.13~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-sun-demo", rpm:"java-1.6.0-sun-demo~1.6.0.13~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-sun-devel", rpm:"java-1.6.0-sun-devel~1.6.0.13~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-sun-jdbc", rpm:"java-1.6.0-sun-jdbc~1.6.0.13~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-sun-plugin", rpm:"java-1.6.0-sun-plugin~1.6.0.13~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-sun-src", rpm:"java-1.6.0-sun-src~1.6.0.13~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
