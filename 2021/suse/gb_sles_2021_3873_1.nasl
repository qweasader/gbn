# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3873.1");
  script_cve_id("CVE-2019-20005", "CVE-2019-20006", "CVE-2019-20007", "CVE-2019-20198", "CVE-2019-20199", "CVE-2019-20200", "CVE-2019-20201", "CVE-2019-20202", "CVE-2021-26220", "CVE-2021-26221", "CVE-2021-26222", "CVE-2021-30485", "CVE-2021-31229", "CVE-2021-31347", "CVE-2021-31348", "CVE-2021-31598");
  script_tag(name:"creation_date", value:"2021-12-03 07:43:42 +0000 (Fri, 03 Dec 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-10 19:15:53 +0000 (Wed, 10 Feb 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3873-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3873-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213873-1/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/ezxml/bugs/23");
  script_xref(name:"URL", value:"https://sourceforge.net/p/ezxml/bugs/14");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netcdf' package(s) announced via the SUSE-SU-2021:3873-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for netcdf fixes the following issues:

Fixed multiple vulnerabilities in ezXML: CVE-2019-20007, CVE-2019-20006,
 CVE-2019-20201, CVE-2019-20202, CVE-2019-20199, CVE-2019-20200,
 CVE-2019-20198, CVE-2021-26221, CVE-2021-26222, CVE-2021-30485,
 CVE-2021-31229, CVE-2021-31347, CVE-2021-31348, CVE-2021-31598
 (bsc#1191856) Note:
 * CVE-2021-26220 [link moved to references] not relevant
 for netcdf: code isn't used.
 * CVE-2019-20005 [link moved to references] Issue cannot
 be reproduced and no patch is available upstream.");

  script_tag(name:"affected", value:"'netcdf' package(s) on SUSE Linux Enterprise Module for HPC 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-hpc", rpm:"libnetcdf-gnu-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-mpich-hpc", rpm:"libnetcdf-gnu-mpich-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-mvapich2-hpc", rpm:"libnetcdf-gnu-mvapich2-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-openmpi3-hpc", rpm:"libnetcdf-gnu-openmpi3-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-openmpi4-hpc", rpm:"libnetcdf-gnu-openmpi4-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-hpc", rpm:"libnetcdf_4_7_4-gnu-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-hpc-debuginfo~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-mpich-hpc", rpm:"libnetcdf_4_7_4-gnu-mpich-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-mpich-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-mpich-hpc-debuginfo~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-mvapich2-hpc", rpm:"libnetcdf_4_7_4-gnu-mvapich2-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-mvapich2-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-mvapich2-hpc-debuginfo~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi3-hpc", rpm:"libnetcdf_4_7_4-gnu-openmpi3-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi3-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-openmpi3-hpc-debuginfo~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi4-hpc", rpm:"libnetcdf_4_7_4-gnu-openmpi4-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi4-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-openmpi4-hpc-debuginfo~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-hpc", rpm:"netcdf-gnu-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-hpc-devel", rpm:"netcdf-gnu-hpc-devel~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-mpich-hpc", rpm:"netcdf-gnu-mpich-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-mpich-hpc-devel", rpm:"netcdf-gnu-mpich-hpc-devel~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-mvapich2-hpc", rpm:"netcdf-gnu-mvapich2-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-mvapich2-hpc-devel", rpm:"netcdf-gnu-mvapich2-hpc-devel~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi3-hpc", rpm:"netcdf-gnu-openmpi3-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi3-hpc-devel", rpm:"netcdf-gnu-openmpi3-hpc-devel~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi4-hpc", rpm:"netcdf-gnu-openmpi4-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi4-hpc-devel", rpm:"netcdf-gnu-openmpi4-hpc-devel~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc", rpm:"netcdf_4_7_4-gnu-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-hpc-debuginfo~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-hpc-debugsource~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc-devel", rpm:"netcdf_4_7_4-gnu-hpc-devel~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-hpc-devel-debuginfo~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-hpc-devel-static~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc", rpm:"netcdf_4_7_4-gnu-mpich-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-mpich-hpc-debuginfo~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-mpich-hpc-debugsource~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc-devel", rpm:"netcdf_4_7_4-gnu-mpich-hpc-devel~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-mpich-hpc-devel-debuginfo~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-mpich-hpc-devel-static~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc-debuginfo~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc-debugsource~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc-devel", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc-devel~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc-devel-debuginfo~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc-devel-static~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc-debuginfo~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc-debugsource~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc-devel", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc-devel~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc-devel-debuginfo~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc-devel-static~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc-debuginfo~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc-debugsource~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc-devel", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc-devel~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc-devel-debuginfo~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc-devel-static~4.7.4~4.3.2", rls:"SLES15.0SP3"))) {
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
