# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1468.1");
  script_cve_id("CVE-2017-7960", "CVE-2017-7961", "CVE-2017-8834", "CVE-2017-8871");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-19 19:12:00 +0000 (Wed, 19 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1468-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3|SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1468-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191468-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcroco' package(s) announced via the SUSE-SU-2019:1468-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libcroco fixes the following issues:

Security issues fixed:
CVE-2017-7960: Fixed heap overflow (input: check end of input before
 reading a byte) (bsc#1034481).

CVE-2017-7961: Fixed undefined behavior (tknzr: support only max long
 rgb values) (bsc#1034482).

CVE-2017-8834: Fixed denial of service (memory allocation error) via a
 crafted CSS file (bsc#1043898).

CVE-2017-8871: Fixed denial of service (infinite loop and CPU
 consumption) via a crafted CSS file (bsc#1043899).");

  script_tag(name:"affected", value:"'libcroco' package(s) on SUSE CaaS Platform 3.0, SUSE CaaS Platform ALL, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3", rpm:"libcroco-0_6-3~0.6.11~12.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-32bit", rpm:"libcroco-0_6-3-32bit~0.6.11~12.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-debuginfo", rpm:"libcroco-0_6-3-debuginfo~0.6.11~12.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-debuginfo-32bit", rpm:"libcroco-0_6-3-debuginfo-32bit~0.6.11~12.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-debuginfo", rpm:"libcroco-debuginfo~0.6.11~12.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-debugsource", rpm:"libcroco-debugsource~0.6.11~12.3.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3", rpm:"libcroco-0_6-3~0.6.11~12.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-32bit", rpm:"libcroco-0_6-3-32bit~0.6.11~12.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-debuginfo", rpm:"libcroco-0_6-3-debuginfo~0.6.11~12.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-debuginfo-32bit", rpm:"libcroco-0_6-3-debuginfo-32bit~0.6.11~12.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-debuginfo", rpm:"libcroco-debuginfo~0.6.11~12.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-debugsource", rpm:"libcroco-debugsource~0.6.11~12.3.1", rls:"SLES12.0SP4"))) {
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
