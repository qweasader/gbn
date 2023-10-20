# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0289");
  script_cve_id("CVE-2020-10730", "CVE-2020-10745", "CVE-2020-10760", "CVE-2020-14303");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-23 05:15:00 +0000 (Mon, 23 Nov 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0289)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0289");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0289.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26893");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2020-10730.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2020-10745.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2020-10760.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2020-14303.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/history/samba-4.10.17.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4409-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ldb, samba' package(s) announced via the MGASA-2020-0289 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated samba packages fix security vulnerabilities:

Andrew Bartlett discovered that Samba incorrectly handled certain LDAP
queries. A remote attacker could use this issue to cause Samba to crash,
resulting in a denial of service, or possibly execute arbitrary code
(CVE-2020-10730).

Douglas Bagnall discovered that Samba incorrectly handled certain queries.
A remote attacker could possibly use this issue to cause a denial of
service (CVE-2020-10745).

Andrei Popa discovered that Samba incorrectly handled certain LDAP
queries. A remote attacker could use this issue to cause Samba to crash,
resulting in a denial of service, or possibly execute arbitrary code
(CVE-2020-10760).

The AD DC NBT server in Samba 4.0 will enter a CPU spin and not process further
requests once it receives a empty (zero-length) UDP packet to port 137
(CVE-2020-14303).");

  script_tag(name:"affected", value:"'ldb, samba' package(s) on Mageia 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"ctdb", rpm:"ctdb~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctdb-tests", rpm:"ctdb-tests~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ldb", rpm:"ldb~1.5.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ldb-utils", rpm:"ldb-utils~1.5.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64heimntlm-samba4_1", rpm:"lib64heimntlm-samba4_1~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdc-samba4_2", rpm:"lib64kdc-samba4_2~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ldb-devel", rpm:"lib64ldb-devel~1.5.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ldb1", rpm:"lib64ldb1~1.5.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pyldb-util-devel", rpm:"lib64pyldb-util-devel~1.5.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pyldb-util1", rpm:"lib64pyldb-util1~1.5.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba-dc0", rpm:"lib64samba-dc0~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba-devel", rpm:"lib64samba-devel~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba-test0", rpm:"lib64samba-test0~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba1", rpm:"lib64samba1~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbclient-devel", rpm:"lib64smbclient-devel~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wbclient-devel", rpm:"lib64wbclient-devel~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wbclient0", rpm:"lib64wbclient0~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheimntlm-samba4_1", rpm:"libheimntlm-samba4_1~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdc-samba4_2", rpm:"libkdc-samba4_2~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb-devel", rpm:"libldb-devel~1.5.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb1", rpm:"libldb1~1.5.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpyldb-util-devel", rpm:"libpyldb-util-devel~1.5.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpyldb-util1", rpm:"libpyldb-util1~1.5.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-dc0", rpm:"libsamba-dc0~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-devel", rpm:"libsamba-devel~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-test0", rpm:"libsamba-test0~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba1", rpm:"libsamba1~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-ldb", rpm:"python2-ldb~1.5.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-samba", rpm:"python2-samba~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ldb", rpm:"python3-ldb~1.5.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-samba", rpm:"python3-samba~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dc", rpm:"samba-dc~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-krb5-printing", rpm:"samba-krb5-printing~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-pidl", rpm:"samba-pidl~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-test", rpm:"samba-test~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-krb5-locator", rpm:"samba-winbind-krb5-locator~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-modules", rpm:"samba-winbind-modules~4.10.17~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
