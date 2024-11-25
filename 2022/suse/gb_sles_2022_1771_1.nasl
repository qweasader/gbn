# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1771.1");
  script_cve_id("CVE-2022-29155");
  script_tag(name:"creation_date", value:"2022-05-23 04:27:55 +0000 (Mon, 23 May 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-12 19:22:23 +0000 (Thu, 12 May 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1771-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1771-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221771-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap2' package(s) announced via the SUSE-SU-2022:1771-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openldap2 fixes the following issues:

CVE-2022-29155: Fixed SQL injection in back-sql (bsc#1199240).

Fixed issue with SASL init that crashed slapd at startup under certain
 conditions (bsc#1198383).");

  script_tag(name:"affected", value:"'openldap2' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2", rpm:"libldap-2_4-2~2.4.41~22.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-32bit", rpm:"libldap-2_4-2-32bit~2.4.41~22.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-debuginfo", rpm:"libldap-2_4-2-debuginfo~2.4.41~22.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-debuginfo-32bit", rpm:"libldap-2_4-2-debuginfo-32bit~2.4.41~22.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2", rpm:"openldap2~2.4.41~22.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-meta", rpm:"openldap2-back-meta~2.4.41~22.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-meta-debuginfo", rpm:"openldap2-back-meta-debuginfo~2.4.41~22.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-client", rpm:"openldap2-client~2.4.41~22.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-client-debuginfo", rpm:"openldap2-client-debuginfo~2.4.41~22.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-debuginfo", rpm:"openldap2-debuginfo~2.4.41~22.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-debugsource", rpm:"openldap2-debugsource~2.4.41~22.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-doc", rpm:"openldap2-doc~2.4.41~22.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-ppolicy-check-password", rpm:"openldap2-ppolicy-check-password~1.2~22.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-ppolicy-check-password-debuginfo", rpm:"openldap2-ppolicy-check-password-debuginfo~1.2~22.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2", rpm:"libldap-2_4-2~2.4.41~22.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-32bit", rpm:"libldap-2_4-2-32bit~2.4.41~22.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-debuginfo", rpm:"libldap-2_4-2-debuginfo~2.4.41~22.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-debuginfo-32bit", rpm:"libldap-2_4-2-debuginfo-32bit~2.4.41~22.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2", rpm:"openldap2~2.4.41~22.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-meta", rpm:"openldap2-back-meta~2.4.41~22.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-meta-debuginfo", rpm:"openldap2-back-meta-debuginfo~2.4.41~22.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-client", rpm:"openldap2-client~2.4.41~22.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-client-debuginfo", rpm:"openldap2-client-debuginfo~2.4.41~22.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-debuginfo", rpm:"openldap2-debuginfo~2.4.41~22.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-debugsource", rpm:"openldap2-debugsource~2.4.41~22.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-doc", rpm:"openldap2-doc~2.4.41~22.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-ppolicy-check-password", rpm:"openldap2-ppolicy-check-password~1.2~22.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-ppolicy-check-password-debuginfo", rpm:"openldap2-ppolicy-check-password-debuginfo~1.2~22.10.1", rls:"SLES12.0SP5"))) {
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
