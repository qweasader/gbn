# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2346.1");
  script_cve_id("CVE-2023-32324");
  script_tag(name:"creation_date", value:"2023-06-02 04:22:09 +0000 (Fri, 02 Jun 2023)");
  script_version("2023-06-20T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:26 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-08 14:32:00 +0000 (Thu, 08 Jun 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2346-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2346-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232346-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the SUSE-SU-2023:2346-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cups fixes the following issues:

CVE-2023-32324: Fixed a buffer overflow in format_log_line() which could cause a denial-of-service (bsc#1211643).");

  script_tag(name:"affected", value:"'cups' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~1.7.5~20.39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~1.7.5~20.39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client-debuginfo", rpm:"cups-client-debuginfo~1.7.5~20.39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~1.7.5~20.39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debugsource", rpm:"cups-debugsource~1.7.5~20.39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.7.5~20.39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-32bit", rpm:"cups-libs-32bit~1.7.5~20.39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-debuginfo", rpm:"cups-libs-debuginfo~1.7.5~20.39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-debuginfo-32bit", rpm:"cups-libs-debuginfo-32bit~1.7.5~20.39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~1.7.5~20.39.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~1.7.5~20.39.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client-debuginfo", rpm:"cups-client-debuginfo~1.7.5~20.39.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~1.7.5~20.39.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debugsource", rpm:"cups-debugsource~1.7.5~20.39.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.7.5~20.39.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-32bit", rpm:"cups-libs-32bit~1.7.5~20.39.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-debuginfo", rpm:"cups-libs-debuginfo~1.7.5~20.39.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-debuginfo-32bit", rpm:"cups-libs-debuginfo-32bit~1.7.5~20.39.1", rls:"SLES12.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~1.7.5~20.39.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~1.7.5~20.39.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client-debuginfo", rpm:"cups-client-debuginfo~1.7.5~20.39.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~1.7.5~20.39.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debugsource", rpm:"cups-debugsource~1.7.5~20.39.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.7.5~20.39.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-32bit", rpm:"cups-libs-32bit~1.7.5~20.39.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-debuginfo", rpm:"cups-libs-debuginfo~1.7.5~20.39.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-debuginfo-32bit", rpm:"cups-libs-debuginfo-32bit~1.7.5~20.39.1", rls:"SLES12.0SP5"))) {
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
