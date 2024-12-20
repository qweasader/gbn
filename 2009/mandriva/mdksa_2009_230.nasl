# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64839");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
  script_cve_id("CVE-2009-1376", "CVE-2009-2694", "CVE-2009-3025", "CVE-2009-3026", "CVE-2009-2703", "CVE-2009-3083", "CVE-2009-3084", "CVE-2009-3085");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:230 (pidgin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2009\.0|2009\.1|mes5)");
  script_tag(name:"insight", value:"Security vulnerabilities has been identified and fixed in pidgin:

The msn_slplink_process_msg function in
libpurple/protocols/msn/slplink.c in libpurple, as used in Pidgin
(formerly Gaim) before 2.5.9 and Adium 1.3.5 and earlier, allows
remote attackers to execute arbitrary code or cause a denial of service
(memory corruption and application crash) by sending multiple crafted
SLP (aka MSNSLP) messages to trigger an overwrite of an arbitrary
memory location.  NOTE: this issue reportedly exists because of an
incomplete fix for CVE-2009-1376 (CVE-2009-2694).

Unspecified vulnerability in Pidgin 2.6.0 allows remote attackers
to cause a denial of service (crash) via a link in a Yahoo IM
(CVE-2009-3025)

protocols/jabber/auth.c in libpurple in Pidgin 2.6.0, and possibly
other versions, does not follow the require TLS/SSL preference
when connecting to older Jabber servers that do not follow the XMPP
specification, which causes libpurple to connect to the server without
the expected encryption and allows remote attackers to sniff sessions
(CVE-2009-3026).

libpurple/protocols/irc/msgs.c in the IRC protocol plugin in libpurple
in Pidgin before 2.6.2 allows remote IRC servers to cause a denial
of service (NULL pointer dereference and application crash) via a
TOPIC message that lacks a topic string (CVE-2009-2703).

The msn_slp_sip_recv function in libpurple/protocols/msn/slp.c in the
MSN protocol plugin in libpurple in Pidgin before 2.6.2 allows remote
attackers to cause a denial of service (NULL pointer dereference
and application crash) via an SLP invite message that lacks certain
required fields, as demonstrated by a malformed message from a KMess
client (CVE-2009-3083).

The msn_slp_process_msg function in libpurple/protocols/msn/slpcall.c
in the MSN protocol plugin in libpurple 2.6.0 and 2.6.1, as used in
Pidgin before 2.6.2, allows remote attackers to cause a denial of
service (application crash) via a handwritten (aka Ink) message,
related to an uninitialized variable and the incorrect UTF16-LE
charset name (CVE-2009-3084).

The XMPP protocol plugin in libpurple in Pidgin before 2.6.2 does
not properly handle an error IQ stanza during an attempted fetch of
a custom smiley, which allows remote attackers to cause a denial of
service (application crash) via XHTML-IM content with cid: images
(CVE-2009-3085).

This update provides pidgin 2.6.2, which is not vulnerable to these
issues.

Affected: 2009.0, 2009.1, Enterprise Server 5.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:230");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/");
  script_tag(name:"summary", value:"The remote host is missing an update to pidgin
announced via advisory MDVSA-2009:230.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libfinch0", rpm:"libfinch0~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple0", rpm:"libpurple0~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-bonjour", rpm:"pidgin-bonjour~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-client", rpm:"pidgin-client~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-gevolution", rpm:"pidgin-gevolution~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-i18n", rpm:"pidgin-i18n~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-meanwhile", rpm:"pidgin-meanwhile~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-mono", rpm:"pidgin-mono~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-plugins", rpm:"pidgin-plugins~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-silc", rpm:"pidgin-silc~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-tcl", rpm:"pidgin-tcl~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64finch0", rpm:"lib64finch0~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64purple0", rpm:"lib64purple0~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64purple-devel", rpm:"lib64purple-devel~2.6.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libfinch0", rpm:"libfinch0~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple0", rpm:"libpurple0~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-bonjour", rpm:"pidgin-bonjour~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-client", rpm:"pidgin-client~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-gevolution", rpm:"pidgin-gevolution~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-i18n", rpm:"pidgin-i18n~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-meanwhile", rpm:"pidgin-meanwhile~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-mono", rpm:"pidgin-mono~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-plugins", rpm:"pidgin-plugins~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-silc", rpm:"pidgin-silc~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-tcl", rpm:"pidgin-tcl~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64finch0", rpm:"lib64finch0~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64purple0", rpm:"lib64purple0~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64purple-devel", rpm:"lib64purple-devel~2.6.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libfinch0", rpm:"libfinch0~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple0", rpm:"libpurple0~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-bonjour", rpm:"pidgin-bonjour~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-client", rpm:"pidgin-client~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-gevolution", rpm:"pidgin-gevolution~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-i18n", rpm:"pidgin-i18n~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-meanwhile", rpm:"pidgin-meanwhile~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-mono", rpm:"pidgin-mono~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-plugins", rpm:"pidgin-plugins~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-silc", rpm:"pidgin-silc~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-tcl", rpm:"pidgin-tcl~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64finch0", rpm:"lib64finch0~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64purple0", rpm:"lib64purple0~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64purple-devel", rpm:"lib64purple-devel~2.6.2~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
