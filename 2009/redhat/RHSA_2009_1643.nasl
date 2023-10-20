# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66469");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
  script_cve_id("CVE-2009-3867", "CVE-2009-3868", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3872", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:1643");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(3|4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1643.

The IBM 1.4.2 SR13-FP3 Java release includes the IBM Java 2 Runtime
Environment and the IBM Java 2 Software Development Kit.

This update fixes several vulnerabilities in the IBM Java 2 Runtime
Environment and the IBM Java 2 Software Development Kit. These
vulnerabilities are summarized on the IBM Security alerts page listed in
the References section. (CVE-2009-3867, CVE-2009-3868, CVE-2009-3869,
CVE-2009-3871, CVE-2009-3872, CVE-2009-3873, CVE-2009-3874, CVE-2009-3875,
CVE-2009-3876, CVE-2009-3877)

All users of java-1.4.2-ibm are advised to upgrade to these updated
packages, which contain the IBM 1.4.2 SR13-FP3 Java release. All running
instances of IBM Java must be restarted for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1643.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#critical");
  script_xref(name:"URL", value:"http://www.ibm.com/developerworks/java/jdk/alerts/");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm", rpm:"java-1.4.2-ibm~1.4.2.13.3~1jpp.1.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-demo", rpm:"java-1.4.2-ibm-demo~1.4.2.13.3~1jpp.1.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-devel", rpm:"java-1.4.2-ibm-devel~1.4.2.13.3~1jpp.1.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-jdbc", rpm:"java-1.4.2-ibm-jdbc~1.4.2.13.3~1jpp.1.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-plugin", rpm:"java-1.4.2-ibm-plugin~1.4.2.13.3~1jpp.1.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-src", rpm:"java-1.4.2-ibm-src~1.4.2.13.3~1jpp.1.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm", rpm:"java-1.4.2-ibm~1.4.2.13.3~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-demo", rpm:"java-1.4.2-ibm-demo~1.4.2.13.3~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-devel", rpm:"java-1.4.2-ibm-devel~1.4.2.13.3~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-javacomm", rpm:"java-1.4.2-ibm-javacomm~1.4.2.13.3~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-jdbc", rpm:"java-1.4.2-ibm-jdbc~1.4.2.13.3~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-plugin", rpm:"java-1.4.2-ibm-plugin~1.4.2.13.3~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-src", rpm:"java-1.4.2-ibm-src~1.4.2.13.3~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm", rpm:"java-1.4.2-ibm~1.4.2.13.3~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-demo", rpm:"java-1.4.2-ibm-demo~1.4.2.13.3~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-devel", rpm:"java-1.4.2-ibm-devel~1.4.2.13.3~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-javacomm", rpm:"java-1.4.2-ibm-javacomm~1.4.2.13.3~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-jdbc", rpm:"java-1.4.2-ibm-jdbc~1.4.2.13.3~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-plugin", rpm:"java-1.4.2-ibm-plugin~1.4.2.13.3~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.4.2-ibm-src", rpm:"java-1.4.2-ibm-src~1.4.2.13.3~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
