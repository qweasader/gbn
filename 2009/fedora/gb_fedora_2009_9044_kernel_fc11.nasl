# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64736");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-2691", "CVE-2009-2848", "CVE-2009-2849", "CVE-2009-2847", "CVE-2009-2695", "CVE-2009-2767", "CVE-2009-2692", "CVE-2009-1897", "CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-9044 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"Update Information:

Security fixes:

  - CVE-2009-2691: Information disclosure in proc filesystem

  - CVE-2009-2848: execve: must clear current->child_tid

  - CVE-2009-2849: md: null pointer dereference

  - CVE-2009-2847: Information leak in do_sigaltstack

Restore missing LIRC drivers, dropped in previous release.
Backport upstream fixes that further improve the security of
mmap of low addresses.  (CVE-2009-2695)

ChangeLog:

  * Thu Sep 24(??!!) 2009 Chuck Ebbert  2.6.29.6-217.2.16

  - Fix CVE-2009-2691: local information disclosure in /proc

  * Fri Aug 21 2009 David Woodhouse

  - Fix b43 on iMac G5 (#514787)

  * Tue Aug 18 2009 Kyle McMartin

  - CVE-2009-2848: execve: must clear current->clear_child_tid

  - Cherry pick upstream commits 52dec22e739eec8f3a0154f768a599f5489048bd
which improve mmap_min_addr.

  - CVE-2009-2849: md: avoid dereferencing null ptr when accessing suspend
sysfs attributes.

  - CVE-2009-2847: do_sigaltstack: avoid copying 'stack_t' as a structure
to userspace");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-9044");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel
announced via advisory FEDORA-2009-9044.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=516171");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=515423");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=518132");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=515392");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=517830");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common", rpm:"kernel-debuginfo-common~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAEdebug", rpm:"kernel-PAEdebug~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAEdebug-devel", rpm:"kernel-PAEdebug-devel~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE-debuginfo", rpm:"kernel-PAE-debuginfo~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAEdebug-debuginfo", rpm:"kernel-PAEdebug-debuginfo~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-bootwrapper", rpm:"kernel-bootwrapper~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp-debuginfo", rpm:"kernel-smp-debuginfo~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.29.6~217.2.16.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
