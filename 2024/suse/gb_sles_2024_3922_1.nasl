# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3922.1");
  script_cve_id("CVE-2024-36474", "CVE-2024-42415");
  script_tag(name:"creation_date", value:"2024-11-07 04:17:15 +0000 (Thu, 07 Nov 2024)");
  script_version("2024-11-08T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-11-08 05:05:30 +0000 (Fri, 08 Nov 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-09 16:44:20 +0000 (Wed, 09 Oct 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3922-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3922-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243922-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgsf' package(s) announced via the SUSE-SU-2024:3922-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libgsf fixes the following issues:

CVE-2024-42415, CVE-2024-36474: Fixed integer overflows affecting memory allocation (bsc#1231282, bsc#1231283).");

  script_tag(name:"affected", value:"'libgsf' package(s) on SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Workstation Extension 15-SP5.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libgsf-1-114", rpm:"libgsf-1-114~1.14.50~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsf-1-114-debuginfo", rpm:"libgsf-1-114-debuginfo~1.14.50~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsf-debugsource", rpm:"libgsf-debugsource~1.14.50~150400.3.6.1", rls:"SLES15.0SP4"))) {
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
