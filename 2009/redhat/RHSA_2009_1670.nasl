# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66534");
  script_version("2023-11-07T05:06:14+0000");
  script_tag(name:"last_modification", value:"2023-11-07 05:06:14 +0000 (Tue, 07 Nov 2023)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_cve_id("CVE-2009-3612", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3726");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-03 17:13:00 +0000 (Fri, 03 Nov 2023)");
  script_name("RedHat Security Advisory RHSA-2009:1670");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1670.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes:

  * NULL pointer dereference flaws in the r128 driver. Checks to test if the
Concurrent Command Engine state was initialized were missing in private
IOCTL functions. An attacker could use these flaws to cause a local denial
of service or escalate their privileges. (CVE-2009-3620, Important)

  * a NULL pointer dereference flaw in the NFSv4 implementation. Several
NFSv4 file locking functions failed to check whether a file had been opened
on the server before performing locking operations on it. A local user on a
system with an NFSv4 share mounted could possibly use this flaw to cause a
denial of service or escalate their privileges. (CVE-2009-3726, Important)

  * a flaw in tcf_fill_node(). A certain data structure in this function was
not initialized properly before being copied to user-space. This could lead
to an information leak. (CVE-2009-3612, Moderate)

  * unix_stream_connect() did not check if a UNIX domain socket was in the
shutdown state. This could lead to a deadlock. A local, unprivileged user
could use this flaw to cause a denial of service. (CVE-2009-3621, Moderate)

Knowledgebase DOC-20536 has steps to mitigate NULL pointer dereference
flaws.

Users should upgrade to these updated packages, which contain backported
patches to correct these issues. The system must be rebooted for this
update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1670.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#important");
  script_xref(name:"URL", value:"http://kbase.redhat.com/faq/docs/DOC-20536");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE-debuginfo", rpm:"kernel-PAE-debuginfo~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common", rpm:"kernel-debuginfo-common~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-kdump-debuginfo", rpm:"kernel-kdump-debuginfo~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-kdump-devel", rpm:"kernel-kdump-devel~2.6.18~164.9.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
