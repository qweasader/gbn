# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66499");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
  script_cve_id("CVE-2009-4131");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 12 FEDORA-2009-13039 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC12");
  script_tag(name:"insight", value:"Update Information:

CVE-2009-4131:  EXT4 - fix insufficient permission checking which could result
in arbitrary data corruption by a local unprivileged user.

ChangeLog:

  * Wed Dec  9 2009 Kyle McMartin  2.6.31.6-166

  - ext4-fix-insufficient-checks-in-EXT4_IOC_MOVE_EXT.patch: CVE-2009-4131
fix insufficient permission checking which could result in arbitrary
data corruption by a local unprivileged user.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-13039");
  script_tag(name:"summary", value:"The remote host is missing an update to the kernel
announced via advisory FEDORA-2009-13039.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=544471");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAEdebug", rpm:"kernel-PAEdebug~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAEdebug-devel", rpm:"kernel-PAEdebug-devel~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common", rpm:"kernel-debuginfo-common~i686~2.6.31.6", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE-debuginfo", rpm:"kernel-PAE-debuginfo~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAEdebug-debuginfo", rpm:"kernel-PAEdebug-debuginfo~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-bootwrapper", rpm:"kernel-bootwrapper~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common", rpm:"kernel-debuginfo-common~ppc~2.6.31.6", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp-debuginfo", rpm:"kernel-smp-debuginfo~2.6.31.6~166.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common", rpm:"kernel-debuginfo-common~ppc64~2.6.31.6", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common", rpm:"kernel-debuginfo-common~x86_64~2.6.31.6", rls:"FC12")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
