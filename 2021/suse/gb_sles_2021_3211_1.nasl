# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3211.1");
  script_cve_id("CVE-2021-22930", "CVE-2021-22931", "CVE-2021-22939", "CVE-2021-22940", "CVE-2021-3672");
  script_tag(name:"creation_date", value:"2021-09-24 07:14:32 +0000 (Fri, 24 Sep 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-24 13:54:00 +0000 (Tue, 24 Aug 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3211-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3211-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213211-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs14' package(s) announced via the SUSE-SU-2021:3211-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs14 fixes the following issues:

CVE-2021-3672: Fixed missing input validation on hostnames (bsc#1188881).

CVE-2021-22931: Fixed improper handling of untypical characters in
 domain names (bsc#1189370).

CVE-2021-22940: Use after free on close http2 on stream canceling
 (bsc#1189368)

CVE-2021-22939: Incomplete validation of rejectUnauthorized parameter
 (bsc#1189369)

CVE-2021-22930: Fixed use after free on close http2 on stream canceling
 (bsc#1188917).");

  script_tag(name:"affected", value:"'nodejs14' package(s) on SUSE Linux Enterprise Module for Web Scripting 15-SP2, SUSE Linux Enterprise Module for Web Scripting 15-SP3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs14", rpm:"nodejs14~14.17.5~5.15.5", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-debuginfo", rpm:"nodejs14-debuginfo~14.17.5~5.15.5", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-debugsource", rpm:"nodejs14-debugsource~14.17.5~5.15.5", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-devel", rpm:"nodejs14-devel~14.17.5~5.15.5", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-docs", rpm:"nodejs14-docs~14.17.5~5.15.5", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm14", rpm:"npm14~14.17.5~5.15.5", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs14", rpm:"nodejs14~14.17.5~5.15.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-debuginfo", rpm:"nodejs14-debuginfo~14.17.5~5.15.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-debugsource", rpm:"nodejs14-debugsource~14.17.5~5.15.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-devel", rpm:"nodejs14-devel~14.17.5~5.15.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-docs", rpm:"nodejs14-docs~14.17.5~5.15.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm14", rpm:"npm14~14.17.5~5.15.5", rls:"SLES15.0SP3"))) {
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
