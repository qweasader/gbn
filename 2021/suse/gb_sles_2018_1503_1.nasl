# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1503.1");
  script_cve_id("CVE-2017-5715");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-14 14:52:07 +0000 (Wed, 14 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1503-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1503-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181503-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oracleasm kmp' package(s) announced via the SUSE-SU-2018:1503-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides rebuilt kernel modules for SUSE Linux Enterprise 12 SP3 products with retpoline enablement to address Spectre Variant 2
(CVE-2017-5715 bsc#1068032).
Following modules have been rebuilt:
- drbd
- oracleasm
- crash
- lttng-modules");

  script_tag(name:"affected", value:"'oracleasm kmp' package(s) on SUSE Linux Enterprise High Availability 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"crash", rpm:"crash~7.1.8~4.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-debuginfo", rpm:"crash-debuginfo~7.1.8~4.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-debugsource", rpm:"crash-debugsource~7.1.8~4.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-default", rpm:"crash-kmp-default~7.1.8_k4.4.131_94.29~4.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-default-debuginfo", rpm:"crash-kmp-default-debuginfo~7.1.8_k4.4.131_94.29~4.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules", rpm:"lttng-modules~2.7.1~8.2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules-debugsource", rpm:"lttng-modules-debugsource~2.7.1~8.2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules-kmp-default", rpm:"lttng-modules-kmp-default~2.7.1_k4.4.131_94.29~8.2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules-kmp-default-debuginfo", rpm:"lttng-modules-kmp-default-debuginfo~2.7.1_k4.4.131_94.29~8.2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-kmp-default", rpm:"oracleasm-kmp-default~2.0.8_k4.4.131_94.29~3.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-kmp-default-debuginfo", rpm:"oracleasm-kmp-default-debuginfo~2.0.8_k4.4.131_94.29~3.8.1", rls:"SLES12.0SP3"))) {
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
