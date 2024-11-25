# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3224.1");
  script_cve_id("CVE-2024-7348");
  script_tag(name:"creation_date", value:"2024-09-13 04:27:55 +0000 (Fri, 13 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-12 15:54:52 +0000 (Mon, 12 Aug 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3224-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3224-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243224-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql16' package(s) announced via the SUSE-SU-2024:3224-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql16 fixes the following issues:

Upgrade to 15.8 (bsc#1229013)
CVE-2024-7348: PostgreSQL relation replacement during pg_dump executes arbitrary SQL. (bsc#1229013)");

  script_tag(name:"affected", value:"'postgresql16' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql15", rpm:"postgresql15~15.8~3.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-contrib", rpm:"postgresql15-contrib~15.8~3.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-contrib-debuginfo", rpm:"postgresql15-contrib-debuginfo~15.8~3.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-debuginfo", rpm:"postgresql15-debuginfo~15.8~3.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-debugsource", rpm:"postgresql15-debugsource~15.8~3.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-docs", rpm:"postgresql15-docs~15.8~3.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plperl", rpm:"postgresql15-plperl~15.8~3.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plperl-debuginfo", rpm:"postgresql15-plperl-debuginfo~15.8~3.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plpython", rpm:"postgresql15-plpython~15.8~3.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plpython-debuginfo", rpm:"postgresql15-plpython-debuginfo~15.8~3.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-pltcl", rpm:"postgresql15-pltcl~15.8~3.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-pltcl-debuginfo", rpm:"postgresql15-pltcl-debuginfo~15.8~3.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server", rpm:"postgresql15-server~15.8~3.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server-debuginfo", rpm:"postgresql15-server-debuginfo~15.8~3.28.1", rls:"SLES12.0SP5"))) {
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
