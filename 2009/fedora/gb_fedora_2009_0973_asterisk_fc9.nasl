# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63391");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_cve_id("CVE-2009-0041");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Fedora Core 9 FEDORA-2009-0973 (asterisk)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC9");
  script_tag(name:"insight", value:"Update Information:

Add a patch to fix a problem with the manager interface.
Update to 1.6.0.5 to fix AST-2009-001 / CVE-2009-0041.

(Original patch in 1.6.0.3 introduced a regression.)

ChangeLog:

  * Fri Jan 23 2009 Jeffrey C. Ollie  - 1.6.0.5-2

  - Add a patch to fix a problem with the manager interface.

  * Fri Jan 23 2009 Jeffrey C. Ollie  - 1.6.0.5-1

  - Update to 1.6.0.5 to fix regressions caused by fixes for
AST-2009-001/CVE-2009-0041 (Asterisk 1.6.0.4 was never released).

  * Thu Jan  8 2009 Jeffrey C. Ollie  - 1.6.0.3-1

  - Update to 1.6.0.3 to fix AST-2009-001/CVE-2009-0041

  * Sun Jan  4 2009 Jeffrey C. Ollie  - 1.6.0.2-4

  - Fedora Directory Server compatibility patch/subpackage. BZ#452176

  * Sun Jan  4 2009 Jeffrey C. Ollie  - 1.6.0.2-3

  - Don't package func_curl in the main package. BZ#475910

  - Fix up paths. BZ#477238

  * Sun Jan  4 2009 Jeffrey C. Ollie  - 1.6.0.2-2

  - Add patch to fix compilation on PPC

  * Sun Jan  4 2009 Jeffrey C. Ollie  - 1.6.0.2-1

  - Update to 1.6.0.2");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update asterisk' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-0973");
  script_tag(name:"summary", value:"The remote host is missing an update to asterisk
announced via advisory FEDORA-2009-0973.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=480132");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"<td>asterisk", rpm:"<td>asterisk~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk", rpm:"asterisk~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-alsa", rpm:"asterisk-alsa~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-curl", rpm:"asterisk-curl~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-dahdi", rpm:"asterisk-dahdi~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-devel", rpm:"asterisk-devel~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-fax", rpm:"asterisk-fax~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-festival", rpm:"asterisk-festival~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-firmware", rpm:"asterisk-firmware~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-ices", rpm:"asterisk-ices~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-jabber", rpm:"asterisk-jabber~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-jack", rpm:"asterisk-jack~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-ldap", rpm:"asterisk-ldap~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-ldap-fds", rpm:"asterisk-ldap-fds~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-lua", rpm:"asterisk-lua~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-minivm", rpm:"asterisk-minivm~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-misdn", rpm:"asterisk-misdn~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-mobile", rpm:"asterisk-mobile~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-odbc", rpm:"asterisk-odbc~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-oss", rpm:"asterisk-oss~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-portaudio", rpm:"asterisk-portaudio~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-postgresql", rpm:"asterisk-postgresql~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-radius", rpm:"asterisk-radius~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-skinny", rpm:"asterisk-skinny~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-snmp", rpm:"asterisk-snmp~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-sqlite", rpm:"asterisk-sqlite~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-tds", rpm:"asterisk-tds~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-unistim", rpm:"asterisk-unistim~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-usbradio", rpm:"asterisk-usbradio~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-voicemail", rpm:"asterisk-voicemail~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-voicemail-imap", rpm:"asterisk-voicemail-imap~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-voicemail-odbc", rpm:"asterisk-voicemail-odbc~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-voicemail-plain", rpm:"asterisk-voicemail-plain~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-debuginfo", rpm:"asterisk-debuginfo~1.6.0.5~2.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
