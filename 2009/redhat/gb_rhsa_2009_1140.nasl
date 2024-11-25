# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64337");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-07-06 20:36:15 +0200 (Mon, 06 Jul 2009)");
  script_cve_id("CVE-2007-1558", "CVE-2009-0642", "CVE-2009-1904");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Security Advisory RHSA-2009:1140");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1140.

Ruby is an extensible, interpreted, object-oriented, scripting language. It
has features to process text files and to do system management tasks.

A flaw was found in the way the Ruby POP module processed certain APOP
authentication requests. By sending certain responses when the Ruby APOP
module attempted to authenticate using APOP against a POP server, a remote
attacker could, potentially, acquire certain portions of a user's
authentication credentials. (CVE-2007-1558)

It was discovered that Ruby did not properly check the return value when
verifying X.509 certificates. This could, potentially, allow a remote
attacker to present an invalid X.509 certificate, and have Ruby treat it as
valid. (CVE-2009-0642)

A flaw was found in the way Ruby converted BigDecimal objects to Float
numbers. If an attacker were able to provide certain input for the
BigDecimal object converter, they could crash an application using this
class. (CVE-2009-1904)

All Ruby users should upgrade to these updated packages, which contain
backported patches to resolve these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1140.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"irb", rpm:"irb~1.8.1~7.el4_8.3", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.1~7.el4_8.3", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-debuginfo", rpm:"ruby-debuginfo~1.8.1~7.el4_8.3", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.8.1~7.el4_8.3", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-docs", rpm:"ruby-docs~1.8.1~7.el4_8.3", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~1.8.1~7.el4_8.3", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-mode", rpm:"ruby-mode~1.8.1~7.el4_8.3", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-tcltk", rpm:"ruby-tcltk~1.8.1~7.el4_8.3", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.5~5.el5_3.7", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-debuginfo", rpm:"ruby-debuginfo~1.8.5~5.el5_3.7", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-docs", rpm:"ruby-docs~1.8.5~5.el5_3.7", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~1.8.5~5.el5_3.7", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~1.8.5~5.el5_3.7", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-rdoc", rpm:"ruby-rdoc~1.8.5~5.el5_3.7", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-ri", rpm:"ruby-ri~1.8.5~5.el5_3.7", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-tcltk", rpm:"ruby-tcltk~1.8.5~5.el5_3.7", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.8.5~5.el5_3.7", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-mode", rpm:"ruby-mode~1.8.5~5.el5_3.7", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
