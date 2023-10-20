# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66384");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_cve_id("CVE-2009-2408", "CVE-2009-2474");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Mandriva Security Advisory MDVSA-2009:315 (libneon)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2008\.0");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in libneo:

neon before 0.28.6, when OpenSSL is used, does not properly handle a
NUL character in a domain name in the subject's Common Name
(CN) field of an X.509 certificate, which allows man-in-the-middle
attackers to spoof arbitrary SSL servers via a crafted certificate
issued by a legitimate Certification Authority, a related issue to
CVE-2009-2408 (CVE-2009-2474).

Packages for 2008.0 are being provided due to extended support for
Corporate products.

This update provides a solution to these vulnerabilities.

Affected: 2008.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:315");
  script_tag(name:"summary", value:"The remote host is missing an update to libneon
announced via advisory MDVSA-2009:315.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libneon0.24", rpm:"libneon0.24~0.24.7~19.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.24-devel", rpm:"libneon0.24-devel~0.24.7~19.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.24-static-devel", rpm:"libneon0.24-static-devel~0.24.7~19.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.26", rpm:"libneon0.26~0.26.4~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.26-devel", rpm:"libneon0.26-devel~0.26.4~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.26-static-devel", rpm:"libneon0.26-static-devel~0.26.4~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.24", rpm:"lib64neon0.24~0.24.7~19.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.24-devel", rpm:"lib64neon0.24-devel~0.24.7~19.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.24-static-devel", rpm:"lib64neon0.24-static-devel~0.24.7~19.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.26", rpm:"lib64neon0.26~0.26.4~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.26-devel", rpm:"lib64neon0.26-devel~0.26.4~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.26-static-devel", rpm:"lib64neon0.26-static-devel~0.26.4~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
