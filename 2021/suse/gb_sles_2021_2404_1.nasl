# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2404.1");
  script_cve_id("CVE-2021-33910");
  script_tag(name:"creation_date", value:"2021-07-21 06:49:19 +0000 (Wed, 21 Jul 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-29 17:50:00 +0000 (Thu, 29 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2404-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2404-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212404-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the SUSE-SU-2021:2404-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following issues:

CVE-2021-33910: Fixed a denial of service in systemd via
 unit_name_path_escape() (bsc#1188063)

Skip udev rules if 'elevator=' is used (bsc#1184994)");

  script_tag(name:"affected", value:"'systemd' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit", rpm:"libsystemd0-32bit~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit-debuginfo", rpm:"libsystemd0-32bit-debuginfo~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-debuginfo", rpm:"libsystemd0-debuginfo~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-devel", rpm:"libudev-devel~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit", rpm:"libudev1-32bit~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit-debuginfo", rpm:"libudev1-32bit-debuginfo~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-debuginfo", rpm:"libudev1-debuginfo~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit", rpm:"systemd-32bit~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit-debuginfo", rpm:"systemd-32bit-debuginfo~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-container", rpm:"systemd-container~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-container-debuginfo", rpm:"systemd-container-debuginfo~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-coredump", rpm:"systemd-coredump~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-coredump-debuginfo", rpm:"systemd-coredump-debuginfo~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debuginfo", rpm:"systemd-debuginfo~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debugsource", rpm:"systemd-debugsource~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~234~24.90.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-debuginfo", rpm:"udev-debuginfo~234~24.90.1", rls:"SLES15.0SP2"))) {
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
