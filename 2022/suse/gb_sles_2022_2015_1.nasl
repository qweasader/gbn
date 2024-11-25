# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2015.1");
  script_cve_id("CVE-2019-14250");
  script_tag(name:"creation_date", value:"2022-06-08 14:09:05 +0000 (Wed, 08 Jun 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-29 20:29:52 +0000 (Mon, 29 Jul 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2015-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2015-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222015-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gcc48' package(s) announced via the SUSE-SU-2022:2015-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gcc48 fixes the following issues:

CVE-2019-14250: Fixed an integer overflow that could lead to an invalid
 memory access (bsc#1142649).

Non-security fixes:

Fixed an issue with manual page builds (bsc#1185395).

Fixed an issue with static initializers (bsc#1177947).

Fixed an issue with exception handling on s390x (bsc#1161913).");

  script_tag(name:"affected", value:"'gcc48' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"cpp48", rpm:"cpp48~4.8.5~31.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp48-debuginfo", rpm:"cpp48-debuginfo~4.8.5~31.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc48-32bit", rpm:"gcc48-32bit~4.8.5~31.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc48", rpm:"gcc48~4.8.5~31.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc48-c++", rpm:"gcc48-c++~4.8.5~31.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc48-c++-debuginfo", rpm:"gcc48-c++-debuginfo~4.8.5~31.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc48-debuginfo", rpm:"gcc48-debuginfo~4.8.5~31.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc48-debugsource", rpm:"gcc48-debugsource~4.8.5~31.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc48-info", rpm:"gcc48-info~4.8.5~31.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc48-locale", rpm:"gcc48-locale~4.8.5~31.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan0-32bit", rpm:"libasan0-32bit~4.8.5~31.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan0", rpm:"libasan0~4.8.5~31.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan0-debuginfo", rpm:"libasan0-debuginfo~4.8.5~31.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++48-devel-32bit", rpm:"libstdc++48-devel-32bit~4.8.5~31.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++48-devel", rpm:"libstdc++48-devel~4.8.5~31.26.1", rls:"SLES12.0SP5"))) {
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
