# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64077");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
  script_cve_id("CVE-2008-3528", "CVE-2008-3525", "CVE-2008-3831", "CVE-2008-2750", "CVE-2009-1439", "CVE-2009-1633");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Fedora Core 9 FEDORA-2009-5383 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC9");
  script_tag(name:"insight", value:"Update Information:

Update to kernel 2.6.27.24

Includes ext4 bug fixes from Fedora 11.
Updates the atl2 network driver to version 2.0.5

ChangeLog:

  * Wed May 20 2009 Chuck Ebbert   2.6.27.24-78.2.53

  - Allow building the F-9 kernel on F-11.

  * Wed May 20 2009 Chuck Ebbert   2.6.27.24-78.2.52

  - ext4 fixes from Fedora 11:
linux-2.6-ext4-clear-unwritten-flag.patch
linux-2.6-ext4-fake-delalloc-bno.patch
linux-2.6-ext4-fix-i_cached_extent-race.patch
linux-2.6-ext4-prealloc-fixes.patch

  * Wed May 20 2009 Chuck Ebbert  2.6.27.24-78.2.51

  - Linux 2.6.27.24

  - Dropped patches, merged upstream:
cifs-fix-unicode-string-area-word-alignment-2.6.27.patch

  - Update atl2 driver to version 2.0.5");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-5383");
  script_tag(name:"summary", value:"The remote host is missing an update to the kernel
announced via advisory FEDORA-2009-5383.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=494275");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496572");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common", rpm:"kernel-debuginfo-common~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAEdebug", rpm:"kernel-PAEdebug~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAEdebug-devel", rpm:"kernel-PAEdebug-devel~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE-debuginfo", rpm:"kernel-PAE-debuginfo~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAEdebug-debuginfo", rpm:"kernel-PAEdebug-debuginfo~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-bootwrapper", rpm:"kernel-bootwrapper~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp-debuginfo", rpm:"kernel-smp-debuginfo~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-kdump-devel", rpm:"kernel-kdump-devel~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-kdump-debuginfo", rpm:"kernel-kdump-debuginfo~2.6.27.24~78.2.53.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
