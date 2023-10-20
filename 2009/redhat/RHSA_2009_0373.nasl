# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63643");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
  script_cve_id("CVE-2009-0784");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:0373");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0373.

SystemTap is an instrumentation infrastructure for systems running version
2.6 of the Linux kernel. SystemTap scripts can collect system operations
data, greatly simplifying information gathering. Collected data can then
assist in performance measuring, functional testing, and performance and
function problem diagnosis.

A race condition was discovered in SystemTap that could allow users in the
stapusr group to elevate privileges to that of members of the stapdev group
(and hence root), bypassing directory confinement restrictions and allowing
them to insert arbitrary SystemTap kernel modules. (CVE-2009-0784)

Note: This issue was only exploitable if another SystemTap kernel module
was placed in the systemtap/ module directory for the currently running
kernel.

Red Hat would like to thank Erik Sjoelund for reporting this issue.

SystemTap users should upgrade to these updated packages, which contain a
backported patch to correct this issue.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0373.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"systemtap", rpm:"systemtap~0.6.2~2.el4_7", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"systemtap-debuginfo", rpm:"systemtap-debuginfo~0.6.2~2.el4_7", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"systemtap-runtime", rpm:"systemtap-runtime~0.6.2~2.el4_7", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"systemtap-testsuite", rpm:"systemtap-testsuite~0.6.2~2.el4_7", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"systemtap", rpm:"systemtap~0.7.2~3.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"systemtap-client", rpm:"systemtap-client~0.7.2~3.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"systemtap-debuginfo", rpm:"systemtap-debuginfo~0.7.2~3.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"systemtap-runtime", rpm:"systemtap-runtime~0.7.2~3.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"systemtap-server", rpm:"systemtap-server~0.7.2~3.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"systemtap-testsuite", rpm:"systemtap-testsuite~0.7.2~3.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
