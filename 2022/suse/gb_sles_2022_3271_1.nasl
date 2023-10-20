# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3271.1");
  script_cve_id("CVE-2017-6512");
  script_tag(name:"creation_date", value:"2022-09-15 04:54:24 +0000 (Thu, 15 Sep 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-29 20:24:00 +0000 (Wed, 29 Apr 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3271-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3271-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223271-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) announced via the SUSE-SU-2022:3271-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for perl fixes the following issues:

CVE-2017-6512: Fixed File::Path rmtree/remove_tree race condition
 (bsc#1047178).");

  script_tag(name:"affected", value:"'perl' package(s) on SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Development Tools 15-SP3, SUSE Linux Enterprise Module for Development Tools 15-SP4, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"perl-32bit-debuginfo", rpm:"perl-32bit-debuginfo~5.26.1~150300.17.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.26.1~150300.17.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base-32bit", rpm:"perl-base-32bit~5.26.1~150300.17.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base-32bit-debuginfo", rpm:"perl-base-32bit-debuginfo~5.26.1~150300.17.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base", rpm:"perl-base~5.26.1~150300.17.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base-debuginfo", rpm:"perl-base-debuginfo~5.26.1~150300.17.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-core-DB_File", rpm:"perl-core-DB_File~5.26.1~150300.17.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-core-DB_File-debuginfo", rpm:"perl-core-DB_File-debuginfo~5.26.1~150300.17.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-debuginfo", rpm:"perl-debuginfo~5.26.1~150300.17.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-debugsource", rpm:"perl-debugsource~5.26.1~150300.17.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-doc", rpm:"perl-doc~5.26.1~150300.17.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-32bit", rpm:"perl-32bit~5.26.1~150300.17.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"perl-32bit-debuginfo", rpm:"perl-32bit-debuginfo~5.26.1~150300.17.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.26.1~150300.17.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base-32bit", rpm:"perl-base-32bit~5.26.1~150300.17.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base-32bit-debuginfo", rpm:"perl-base-32bit-debuginfo~5.26.1~150300.17.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base", rpm:"perl-base~5.26.1~150300.17.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base-debuginfo", rpm:"perl-base-debuginfo~5.26.1~150300.17.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-core-DB_File", rpm:"perl-core-DB_File~5.26.1~150300.17.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-core-DB_File-debuginfo", rpm:"perl-core-DB_File-debuginfo~5.26.1~150300.17.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-debuginfo", rpm:"perl-debuginfo~5.26.1~150300.17.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-debugsource", rpm:"perl-debugsource~5.26.1~150300.17.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-doc", rpm:"perl-doc~5.26.1~150300.17.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-32bit", rpm:"perl-32bit~5.26.1~150300.17.11.1", rls:"SLES15.0SP4"))) {
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
