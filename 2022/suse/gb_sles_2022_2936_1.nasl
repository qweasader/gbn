# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2936.1");
  script_cve_id("CVE-2022-31676");
  script_tag(name:"creation_date", value:"2022-08-30 04:56:20 +0000 (Tue, 30 Aug 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 17:52:02 +0000 (Mon, 29 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2936-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2936-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222936-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'open-vm-tools' package(s) announced via the SUSE-SU-2022:2936-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for open-vm-tools fixes the following issues:

Updated to version 12.1.0 (build 20219665) (bsc#1202733):
 - CVE-2022-31676: Fixed an issue that could allow unprivileged users
 inside a virtual machine to escalate privileges (bsc#1202657).");

  script_tag(name:"affected", value:"'open-vm-tools' package(s) on SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Desktop Applications 15-SP3, SUSE Linux Enterprise Module for Desktop Applications 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libvmtools-devel", rpm:"libvmtools-devel~12.1.0~150300.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0", rpm:"libvmtools0~12.1.0~150300.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0-debuginfo", rpm:"libvmtools0-debuginfo~12.1.0~150300.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~12.1.0~150300.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debuginfo", rpm:"open-vm-tools-debuginfo~12.1.0~150300.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debugsource", rpm:"open-vm-tools-debugsource~12.1.0~150300.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp", rpm:"open-vm-tools-sdmp~12.1.0~150300.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp-debuginfo", rpm:"open-vm-tools-sdmp-debuginfo~12.1.0~150300.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop", rpm:"open-vm-tools-desktop~12.1.0~150300.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop-debuginfo", rpm:"open-vm-tools-desktop-debuginfo~12.1.0~150300.19.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libvmtools-devel", rpm:"libvmtools-devel~12.1.0~150300.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0", rpm:"libvmtools0~12.1.0~150300.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0-debuginfo", rpm:"libvmtools0-debuginfo~12.1.0~150300.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~12.1.0~150300.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debuginfo", rpm:"open-vm-tools-debuginfo~12.1.0~150300.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debugsource", rpm:"open-vm-tools-debugsource~12.1.0~150300.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp", rpm:"open-vm-tools-sdmp~12.1.0~150300.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp-debuginfo", rpm:"open-vm-tools-sdmp-debuginfo~12.1.0~150300.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop", rpm:"open-vm-tools-desktop~12.1.0~150300.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop-debuginfo", rpm:"open-vm-tools-desktop-debuginfo~12.1.0~150300.19.1", rls:"SLES15.0SP4"))) {
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
