# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2006.1");
  script_cve_id("CVE-2022-1048", "CVE-2022-30594");
  script_tag(name:"creation_date", value:"2022-06-08 04:27:07 +0000 (Wed, 08 Jun 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-20 17:33:49 +0000 (Fri, 20 May 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2006-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2006-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222006-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 40 for SLE 12 SP3)' package(s) announced via the SUSE-SU-2022:2006-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 4.4.180-94_147 fixes several issues.

The following security issues were fixed:

CVE-2022-1048: Fixed a race Condition in snd_pcm_hw_free leading to
 use-after-free due to the AB/BA lock with buffer_mutex and mmap_lock
 (bsc#1197597).

CVE-2022-30594: Fixed restriction bypass on setting the
 PT_SUSPEND_SECCOMP flag (bnc#1199602).

Add missing module_mutex lock to module notifier for previous live
 patches (bsc#1199834).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 40 for SLE 12 SP3)' package(s) on SUSE Linux Enterprise Live Patching 12-SP4, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_147-default", rpm:"kgraft-patch-4_4_180-94_147-default~13~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_147-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_147-default-debuginfo~13~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_150-default", rpm:"kgraft-patch-4_4_180-94_150-default~9~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_150-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_150-default-debuginfo~9~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_153-default", rpm:"kgraft-patch-4_4_180-94_153-default~5~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_153-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_153-default-debuginfo~5~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_156-default", rpm:"kgraft-patch-4_4_180-94_156-default~4~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_156-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_156-default-debuginfo~4~2.2", rls:"SLES12.0SP3"))) {
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
