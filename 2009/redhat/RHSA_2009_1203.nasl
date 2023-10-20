# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64593");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2009-2411");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:1203");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1203.

Subversion (SVN) is a concurrent version control system which enables one
or more users to collaborate in developing and maintaining a hierarchy of
files and directories while keeping a history of all changes.

Matt Lewis, of Google, reported multiple heap overflow flaws in Subversion
(server and client) when parsing binary deltas. A malicious user with
commit access to a server could use these flaws to cause a heap overflow on
that server. A malicious server could use these flaws to cause a heap
overflow on a client when it attempts to checkout or update. These heap
overflows can result in a crash or, possibly, arbitrary code execution.
(CVE-2009-2411)

All Subversion users should upgrade to these updated packages, which
contain a backported patch to correct these issues. After installing the
updated packages, the Subversion server must be restarted for the update
to take effect: restart httpd if you are using mod_dav_svn, or restart
svnserve if it is used.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1203.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#important");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"mod_dav_svn", rpm:"mod_dav_svn~1.1.4~3.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.1.4~3.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-debuginfo", rpm:"subversion-debuginfo~1.1.4~3.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.1.4~3.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-perl", rpm:"subversion-perl~1.1.4~3.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mod_dav_svn", rpm:"mod_dav_svn~1.4.2~4.el5_3.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.4.2~4.el5_3.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-debuginfo", rpm:"subversion-debuginfo~1.4.2~4.el5_3.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.4.2~4.el5_3.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-javahl", rpm:"subversion-javahl~1.4.2~4.el5_3.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-perl", rpm:"subversion-perl~1.4.2~4.el5_3.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-ruby", rpm:"subversion-ruby~1.4.2~4.el5_3.1", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
