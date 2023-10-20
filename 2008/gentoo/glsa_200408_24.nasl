# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54654");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0415", "CVE-2004-0685");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200408-24 (Kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple information leaks have been found in the Linux kernel, allowing an
attacker to obtain sensitive data which may be used for further
exploitation of the system.");
  script_tag(name:"solution", value:"Users are encouraged to upgrade to the latest available sources for their
system:

    # emerge sync
    # emerge -pv your-favorite-sources
    # emerge your-favorite-sources

    # # Follow usual procedure for compiling and installing a kernel.
    # # If you use genkernel, run genkernel as you would normally.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200408-24");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=59378");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=59905");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=59769");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200408-24.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"sys-kernel/aa-sources", unaffected: make_list("rge 2.4.23-r2", "ge 2.6.5-r5"), vulnerable: make_list("lt 2.6.5-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/alpha-sources", unaffected: make_list("ge 2.4.21-r12"), vulnerable: make_list("lt 2.4.21-r12"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ck-sources", unaffected: make_list("rge 2.4.26-r1", "ge 2.6.7-r5"), vulnerable: make_list("lt 2.6.7-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/development-sources", unaffected: make_list("ge 2.6.8"), vulnerable: make_list("lt 2.6.8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gentoo-dev-sources", unaffected: make_list("ge 2.6.7-r12"), vulnerable: make_list("lt 2.6.7-r12"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gentoo-sources", unaffected: make_list("rge 2.4.19-r22", "rge 2.4.20-r25", "rge 2.4.22-r16", "rge 2.4.25-r9", "ge 2.4.26-r9"), vulnerable: make_list("lt 2.4.26-r9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/grsec-sources", unaffected: make_list("ge 2.4.27.2.0.1-r1"), vulnerable: make_list("lt 2.4.27.2.0.1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gs-sources", unaffected: make_list("ge 2.4.25_pre7-r11"), vulnerable: make_list("lt 2.4.25_pre7-r11"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hardened-dev-sources", unaffected: make_list("ge 2.6.7-r7"), vulnerable: make_list("lt 2.6.7-r7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hardened-sources", unaffected: make_list("ge 2.4.27-r1"), vulnerable: make_list("lt 2.4.27-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hppa-dev-sources", unaffected: make_list("ge 2.6.7_p14-r1"), vulnerable: make_list("lt 2.6.7_p14-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hppa-sources", unaffected: make_list("ge 2.4.26_p7-r1"), vulnerable: make_list("lt 2.4.26_p7-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ia64-sources", unaffected: make_list("ge 2.4.24-r10"), vulnerable: make_list("lt 2.4.24-r10"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/mips-sources", unaffected: make_list("rge 2.4.25-r8", "rge 2.4.26-r8", "rge 2.6.4-r8", "rge 2.6.6-r8", "ge 2.6.7-r5"), vulnerable: make_list("lt 2.6.6-r8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/mm-sources", unaffected: make_list("ge 2.6.8_rc4-r1"), vulnerable: make_list("lt 2.6.8_rc4-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/openmosix-sources", unaffected: make_list("ge 2.4.24-r4"), vulnerable: make_list("lt 2.4.24-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/pac-sources", unaffected: make_list("ge 2.4.23-r12"), vulnerable: make_list("lt 2.4.23-r12"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/pegasos-dev-sources", unaffected: make_list("ge 2.6.8"), vulnerable: make_list("lt 2.6.8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/rsbac-sources", unaffected: make_list("ge 2.4.26-r5"), vulnerable: make_list("lt 2.4.26-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/rsbac-dev-sources", unaffected: make_list("ge 2.6.7-r5"), vulnerable: make_list("lt 2.6.7-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/selinux-sources", unaffected: make_list("ge 2.4.26-r3"), vulnerable: make_list("lt 2.4.26-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/sparc-sources", unaffected: make_list("ge 2.4.27-r1"), vulnerable: make_list("lt 2.4.27-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/uclinux-sources", unaffected: make_list("rge 2.4.26_p0-r6", "ge 2.6.7_p0-r5"), vulnerable: make_list("lt 2.6.7_p0-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/usermode-sources", unaffected: make_list("rge 2.4.24-r9", "rge 2.4.26-r6", "ge 2.6.6-r6"), vulnerable: make_list("lt 2.6.6-r6"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/vanilla-sources", unaffected: make_list("ge 2.4.27"), vulnerable: make_list("lt 2.4.27"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/vserver-sources", unaffected: make_list("ge 2.4.26.1.28-r4"), vulnerable: make_list("lt 2.4.26.1.28-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/win4lin-sources", unaffected: make_list("rge 2.4.26-r6", "ge 2.6.7-r2"), vulnerable: make_list("lt 2.6.7-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/wolk-sources", unaffected: make_list("rge 4.9-r14", "rge 4.11-r10", "ge 4.14-r7"), vulnerable: make_list("lt 4.14-r7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/xbox-sources", unaffected: make_list("rge 2.4.27-r1", "ge 2.6.7-r5"), vulnerable: make_list("lt 2.6.7-r5"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
