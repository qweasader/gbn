# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64966");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-28 19:09:13 +0200 (Mon, 28 Sep 2009)");
  script_cve_id("CVE-2009-0542");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-9386 (proftpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

This update has a large number of changes from previous Fedora packages. The
highlights are as follows:

  - Update to upstream release 1.3.2a

  - Fix SQL injection vulnerability at login (#485125, CVE-2009-0542)

  - Fix SELinux compatibility (#498375)

  - Fix audit logging (#506735)

  - Fix default configuration (#509251)

  - Many new loadable modules including mod_ctrls_admin and mod_wrap2

  - National Language Support (RFC 2640)

  - Enable/disable common features in /etc/sysconfig/proftpd

ChangeLog:

  * Mon Sep  7 2009 Paul Howarth  1.3.2a-5

  - Add upstream patch for MLSD with dirnames containing glob chars (#521634)

  * Wed Sep  2 2009 Paul Howarth  1.3.2a-4

  - New DSO module: mod_exec (#520214)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update proftpd' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-9386");
  script_tag(name:"summary", value:"The remote host is missing an update to proftpd
announced via advisory FEDORA-2009-9386.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=485125");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"proftpd", rpm:"proftpd~1.3.2a~5.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-ldap", rpm:"proftpd-ldap~1.3.2a~5.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mysql", rpm:"proftpd-mysql~1.3.2a~5.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-postgresql", rpm:"proftpd-postgresql~1.3.2a~5.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-debuginfo", rpm:"proftpd-debuginfo~1.3.2a~5.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
