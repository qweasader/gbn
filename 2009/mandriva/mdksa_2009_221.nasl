# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64693");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2003-1564", "CVE-2009-2473", "CVE-2009-2408", "CVE-2009-2474");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 14:10:59 +0000 (Fri, 02 Feb 2024)");
  script_name("Mandrake Security Advisory MDVSA-2009:221 (libneon0.27)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|2009\.1|4\.0|mes5)");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in libneon0.27:

neon before 0.28.6, when expat is used, does not properly detect
recursion during entity expansion, which allows context-dependent
attackers to cause a denial of service (memory and CPU consumption)
via a crafted XML document containing a large number of nested entity
references, a similar issue to CVE-2003-1564 (CVE-2009-2473).

neon before 0.28.6, when OpenSSL is used, does not properly handle a
'\0' (NUL) character in a domain name in the subject's Common Name
(CN) field of an X.509 certificate, which allows man-in-the-middle
attackers to spoof arbitrary SSL servers via a crafted certificate
issued by a legitimate Certification Authority, a related issue to
CVE-2009-2408 (CVE-2009-2474).

This update provides a solution to these vulnerabilities.

Affected: 2008.1, 2009.0, 2009.1, Corporate 4.0, Enterprise Server 5.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:221");
  script_tag(name:"summary", value:"The remote host is missing an update to libneon0.27
announced via advisory MDVSA-2009:221.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libneon0.27", rpm:"libneon0.27~0.28.3~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-devel", rpm:"libneon0.27-devel~0.28.3~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-static-devel", rpm:"libneon0.27-static-devel~0.28.3~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27", rpm:"lib64neon0.27~0.28.3~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-devel", rpm:"lib64neon0.27-devel~0.28.3~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-static-devel", rpm:"lib64neon0.27-static-devel~0.28.3~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27", rpm:"libneon0.27~0.28.3~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-devel", rpm:"libneon0.27-devel~0.28.3~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-static-devel", rpm:"libneon0.27-static-devel~0.28.3~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27", rpm:"lib64neon0.27~0.28.3~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-devel", rpm:"lib64neon0.27-devel~0.28.3~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-static-devel", rpm:"lib64neon0.27-static-devel~0.28.3~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27", rpm:"libneon0.27~0.28.3~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-devel", rpm:"libneon0.27-devel~0.28.3~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-static-devel", rpm:"libneon0.27-static-devel~0.28.3~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27", rpm:"lib64neon0.27~0.28.3~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-devel", rpm:"lib64neon0.27-devel~0.28.3~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-static-devel", rpm:"lib64neon0.27-static-devel~0.28.3~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27", rpm:"libneon0.27~0.28.3~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-devel", rpm:"libneon0.27-devel~0.28.3~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-static-devel", rpm:"libneon0.27-static-devel~0.28.3~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27", rpm:"lib64neon0.27~0.28.3~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-devel", rpm:"lib64neon0.27-devel~0.28.3~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-static-devel", rpm:"lib64neon0.27-static-devel~0.28.3~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27", rpm:"libneon0.27~0.28.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-devel", rpm:"libneon0.27-devel~0.28.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-static-devel", rpm:"libneon0.27-static-devel~0.28.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27", rpm:"lib64neon0.27~0.28.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-devel", rpm:"lib64neon0.27-devel~0.28.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-static-devel", rpm:"lib64neon0.27-static-devel~0.28.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
