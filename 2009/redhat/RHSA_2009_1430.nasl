# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64832");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
  script_cve_id("CVE-2009-2654", "CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3074", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:1430");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1430.

Mozilla Firefox is an open source Web browser. XULRunner provides the XUL
Runtime environment for Mozilla Firefox. nspr provides the Netscape
Portable Runtime (NSPR).

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2009-3070, CVE-2009-3071, CVE-2009-3072, CVE-2009-3074,
CVE-2009-3075)

A use-after-free flaw was found in Firefox. An attacker could use this flaw
to crash Firefox or, potentially, execute arbitrary code with the
privileges of the user running Firefox. (CVE-2009-3077)

A flaw was found in the way Firefox handles malformed JavaScript. A website
with an object containing malicious JavaScript could execute that
JavaScript with the privileges of the user running Firefox. (CVE-2009-3079)

Descriptions in the dialogs when adding and removing PKCS #11 modules were
not informative. An attacker able to trick a user into installing a
malicious PKCS #11 module could use this flaw to install their own
Certificate Authority certificates on a user's machine, making it possible
to trick the user into believing they are viewing a trusted site or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2009-3076)

A flaw was found in the way Firefox displays the address bar when
window.open() is called in a certain way. An attacker could use this flaw
to conceal a malicious URL, possibly tricking a user into believing they
are viewing a trusted site. (CVE-2009-2654)

A flaw was found in the way Firefox displays certain Unicode characters. An
attacker could use this flaw to conceal a malicious URL, possibly tricking
a user into believing they are viewing a trusted site. (CVE-2009-3078)

For technical details regarding these flaws, refer to the Mozilla security
advisories for Firefox 3.0.14. You can find a link to the Mozilla
advisories in the References section of this errata.

All Firefox users should upgrade to these updated packages, which contain
Firefox version 3.0.14, which corrects these issues. After installing the
update, Firefox must be restarted for the changes to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1430.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#critical");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/known-vulnerabilities/firefox30.html#firefox3.0.14");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.14~1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~3.0.14~1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.7.5~1.el4_8", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspr-debuginfo", rpm:"nspr-debuginfo~4.7.5~1.el4_8", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.7.5~1.el4_8", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.14~1.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~3.0.14~1.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.7.5~1.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspr-debuginfo", rpm:"nspr-debuginfo~4.7.5~1.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~1.9.0.14~1.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xulrunner-debuginfo", rpm:"xulrunner-debuginfo~1.9.0.14~1.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.7.5~1.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~1.9.0.14~1.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xulrunner-devel-unstable", rpm:"xulrunner-devel-unstable~1.9.0.14~1.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
