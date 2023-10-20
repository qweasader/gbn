# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3107.1");
  script_cve_id("CVE-2022-32990");
  script_tag(name:"creation_date", value:"2022-09-07 04:58:49 +0000 (Wed, 07 Sep 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-01 16:57:00 +0000 (Fri, 01 Jul 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3107-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3107-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223107-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gimp' package(s) announced via the SUSE-SU-2022:3107-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gimp fixes the following issues:

CVE-2022-32990: Fixed an unhandled exception which may lead to denial
 of service (bsc#1201192).");

  script_tag(name:"affected", value:"'gimp' package(s) on SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Workstation Extension 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.10.12~150300.9.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-debuginfo", rpm:"gimp-debuginfo~2.10.12~150300.9.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-debugsource", rpm:"gimp-debugsource~2.10.12~150300.9.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel", rpm:"gimp-devel~2.10.12~150300.9.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel-debuginfo", rpm:"gimp-devel-debuginfo~2.10.12~150300.9.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-lang", rpm:"gimp-lang~2.10.12~150300.9.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-plugin-aa", rpm:"gimp-plugin-aa~2.10.12~150300.9.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-plugin-aa-debuginfo", rpm:"gimp-plugin-aa-debuginfo~2.10.12~150300.9.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0", rpm:"libgimp-2_0-0~2.10.12~150300.9.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-debuginfo", rpm:"libgimp-2_0-0-debuginfo~2.10.12~150300.9.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0", rpm:"libgimpui-2_0-0~2.10.12~150300.9.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-debuginfo", rpm:"libgimpui-2_0-0-debuginfo~2.10.12~150300.9.6.1", rls:"SLES15.0SP3"))) {
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
