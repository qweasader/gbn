# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64861");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
  script_cve_id("CVE-2009-2632");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-9559 (dovecot)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

dovecot-sieve updated to 1.1.7
It is derived from CMU sieve used by cyrus-imapd and was affected by
CVE-2009-2632 too.

ChangeLog:

  * Mon Sep 14 2009 Michal Hlavinka  - 1:1.1.18-2

  - dovecot-sieve updated to 1.1.7

  - fixes bug similar to CVE-2009-2632 (buffer overflow)

  * Wed Jul 29 2009 Michal Hlavinka  - 1:1.1.18-1

  - updated to 1.1.18

  - Maildir++ quota: Quota was sometimes updated wrong when it was
being recalculated.

  - Searching quoted-printable message body internally converted _
characters to spaces and didn't match search keys with _.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update dovecot' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-9559");
  script_tag(name:"summary", value:"The remote host is missing an update to dovecot
announced via advisory FEDORA-2009-9559.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521010");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~1.1.18~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dovecot-devel", rpm:"dovecot-devel~1.1.18~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dovecot-gssapi", rpm:"dovecot-gssapi~1.1.18~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dovecot-ldap", rpm:"dovecot-ldap~1.1.18~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dovecot-managesieve", rpm:"dovecot-managesieve~1.1.18~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dovecot-mysql", rpm:"dovecot-mysql~1.1.18~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dovecot-pgsql", rpm:"dovecot-pgsql~1.1.18~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dovecot-sieve", rpm:"dovecot-sieve~1.1.18~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dovecot-sqlite", rpm:"dovecot-sqlite~1.1.18~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dovecot-debuginfo", rpm:"dovecot-debuginfo~1.1.18~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
