# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64704");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-2692", "CVE-2009-1897", "CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-8649 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"Update Information:

Fix sock_sendpage null pointer dereference. CVE-2009-2692.

ChangeLog:

  * Fri Aug 14 2009 Kyle McMartin  2.6.29.6-217.2.7

  - CVE-2009-2692: Fix sock sendpage NULL ptr deref.

  * Thu Aug 13 2009 Kristian H�gsberg  - 2.6.29.6-217.2.6

  - Backport 0e7ddf7e to fix bad BUG_ON() in i915 gem fence management
code.  Adds drm-i915-gem-bad-bug-on.patch, fixes #514091.

  * Wed Aug 12 2009 John W. Linville  2.6.29.6-217.2.5

  - iwlwifi: fix TX queue race

  * Mon Aug 10 2009 Jarod Wilson  2.6.29.6-217.2.4

  - Add tunable pad threshold support to lirc_imon

  - Blacklist all iMON devices in usbhid driver so lirc_imon can bind

  - Add new device ID to lirc_mceusb (#512483)

  - Enable IR transceiver on the HD PVR

  * Wed Jul 29 2009 Chuck Ebbert  2.6.29.6-217.2.3

  - Don't optimize away NULL pointer tests where pointer is used before the test.
(CVE-2009-1897)

  * Wed Jul 29 2009 Chuck Ebbert  2.6.29.6-217.2.2

  - Fix mmap_min_addr security bugs (CVE-2009-1895)

  * Wed Jul 29 2009 Chuck Ebbert  2.6.29.6-217.2.1

  - Fix eCryptfs overflow issues (CVE-2009-2406, CVE-2009-2407)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8649");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel
announced via advisory FEDORA-2009-8649.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=516949");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common", rpm:"kernel-debuginfo-common~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAEdebug", rpm:"kernel-PAEdebug~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAEdebug-devel", rpm:"kernel-PAEdebug-devel~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE-debuginfo", rpm:"kernel-PAE-debuginfo~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAEdebug-debuginfo", rpm:"kernel-PAEdebug-debuginfo~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-bootwrapper", rpm:"kernel-bootwrapper~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp-debuginfo", rpm:"kernel-smp-debuginfo~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.29.6~217.2.7.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
