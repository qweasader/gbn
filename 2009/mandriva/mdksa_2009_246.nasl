# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64958");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-28 19:09:13 +0200 (Mon, 28 Sep 2009)");
  script_cve_id("CVE-2008-7068", "CVE-2009-3291", "CVE-2009-3292", "CVE-2009-3293");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:246 (php)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(3\.0|4\.0|2\.0)");
  script_tag(name:"insight", value:"Multiple vulnerabilities was discovered and corrected in php:

The dba_replace function in PHP 5.2.6 and 4.x allows context-dependent
attackers to cause a denial of service (file truncation) via a key with
the NULL byte.  NOTE: this might only be a vulnerability in limited
circumstances in which the attacker can modify or add database entries
but does not have permissions to truncate the file (CVE-2008-7068).

The php_openssl_apply_verification_policy function in PHP before
5.2.11 does not properly perform certificate validation, which has
unknown impact and attack vectors, probably related to an ability to
spoof certificates (CVE-2009-3291).

Unspecified vulnerability in PHP before 5.2.11 has unknown impact
and attack vectors related to missing sanity checks around exif
processing. (CVE-2009-3292)

Unspecified vulnerability in the imagecolortransparent function in
PHP before 5.2.11 has unknown impact and attack vectors related to
an incorrect sanity check for the color index. (CVE-2009-3293)

This update provides a solution to these vulnerabilities.

Affected: Corporate 3.0, Corporate 4.0, Multi Network Firewall 2.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:246");
  script_tag(name:"summary", value:"The remote host is missing an update to php
announced via advisory MDVSA-2009:246.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libphp_common432", rpm:"libphp_common432~4.3.4~4.30.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php432-devel", rpm:"php432-devel~4.3.4~4.30.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-cgi", rpm:"php-cgi~4.3.4~4.30.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~4.3.4~4.30.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-dba_bundle", rpm:"php-dba_bundle~4.3.4~1.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~4.3.4~1.8.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64php_common432", rpm:"lib64php_common432~4.3.4~4.30.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libphp4_common4", rpm:"libphp4_common4~4.4.4~1.12.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libphp5_common5", rpm:"libphp5_common5~5.1.6~1.14.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php4-cgi", rpm:"php4-cgi~4.4.4~1.12.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php4-cli", rpm:"php4-cli~4.4.4~1.12.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php4-dba_bundle", rpm:"php4-dba_bundle~4.4.4~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php4-devel", rpm:"php4-devel~4.4.4~1.12.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php4-exif", rpm:"php4-exif~4.4.4~1.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-cgi", rpm:"php-cgi~5.1.6~1.14.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.1.6~1.14.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~5.1.6~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~5.1.6~1.14.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-exif", rpm:"php-exif~5.1.6~1.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-fcgi", rpm:"php-fcgi~5.1.6~1.14.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~5.1.6~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64php4_common4", rpm:"lib64php4_common4~4.4.4~1.12.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64php5_common5", rpm:"lib64php5_common5~5.1.6~1.14.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libphp_common432", rpm:"libphp_common432~4.3.4~4.30.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php432-devel", rpm:"php432-devel~4.3.4~4.30.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-cgi", rpm:"php-cgi~4.3.4~4.30.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~4.3.4~4.30.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~4.3.4~1.8.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
