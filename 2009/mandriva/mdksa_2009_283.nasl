# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66083");
  script_version("2024-01-01T05:05:52+0000");
  script_tag(name:"last_modification", value:"2024-01-01 05:05:52 +0000 (Mon, 01 Jan 2024)");
  script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0163", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-1179", "CVE-2009-0791", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-0949", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-1196", "CVE-2009-3608", "CVE-2009-3609");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 15:21:00 +0000 (Thu, 28 Dec 2023)");
  script_name("Mandrake Security Advisory MDVSA-2009:283 (cups)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(3\.0|2\.0)");
  script_tag(name:"insight", value:"This update corrects the problems.

Affected: Corporate 3.0, Multi Network Firewall 2.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:283");
  script_tag(name:"summary", value:"The remote host is missing an update to cups
announced via advisory MDVSA-2009:283. For details,
please visit the referenced security advisories.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.1.20~5.21.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-common", rpm:"cups-common~1.1.20~5.21.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-serial", rpm:"cups-serial~1.1.20~5.21.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~1.1.20~5.21.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcups2-devel", rpm:"libcups2-devel~1.1.20~5.21.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64cups2", rpm:"lib64cups2~1.1.20~5.21.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64cups2-devel", rpm:"lib64cups2-devel~1.1.20~5.21.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.1.20~5.21.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-common", rpm:"cups-common~1.1.20~5.21.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-serial", rpm:"cups-serial~1.1.20~5.21.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~1.1.20~5.21.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcups2-devel", rpm:"libcups2-devel~1.1.20~5.21.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
