# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0481");
  script_cve_id("CVE-2021-33054");
  script_tag(name:"creation_date", value:"2023-01-02 04:14:00 +0000 (Mon, 02 Jan 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-10 13:49:52 +0000 (Thu, 10 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0481)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0481");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0481.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29255");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2707");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-5029");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sogo, sope' package(s) announced via the MGASA-2022-0481 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Missing SAML signature validation in the SOGo groupware could result in
impersonation attacks. (CVE-2021-33054)");

  script_tag(name:"affected", value:"'sogo, sope' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"libGDLAccess4_9", rpm:"libGDLAccess4_9~5.6.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGDLContentStore4_9", rpm:"libGDLContentStore4_9~5.6.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libNGCards4_9", rpm:"libNGCards4_9~5.6.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libNGLdap4_9", rpm:"libNGLdap4_9~5.6.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libNGMime4_9", rpm:"libNGMime4_9~5.6.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sogo", rpm:"sogo~5.6.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sogo-devel", rpm:"sogo-devel~5.6.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sogo-slapd-sockd", rpm:"sogo-slapd-sockd~5.6.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sogo-tool", rpm:"sogo-tool~5.6.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sope", rpm:"sope~5.6.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sope-appserver", rpm:"sope-appserver~5.6.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sope-core", rpm:"sope-core~5.6.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sope-devel", rpm:"sope-devel~5.6.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sope-gdl1-mysql", rpm:"sope-gdl1-mysql~5.6.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sope-gdl1-postgresql", rpm:"sope-gdl1-postgresql~5.6.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sope-xml", rpm:"sope-xml~5.6.0~1.1.mga8", rls:"MAGEIA8"))) {
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
