# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3258.1");
  script_cve_id("CVE-2018-20856", "CVE-2019-10220", "CVE-2019-13272", "CVE-2019-15239");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-03 11:15:00 +0000 (Fri, 03 Jan 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3258-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3258-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193258-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 25 for SLE 12 SP3)' package(s) announced via the SUSE-SU-2019:3258-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 4.4.178-94_91 fixes several issues.

The following security issues were fixed:
CVE-2018-20856: Fixed a use-after-free in block/blk-core.c due to
 improper error handling (bsc#1156331).

CVE-2019-13272: Fixed a privilege escalation from user to root due to
 improper handling of credentials by leveraging certain scenarios with a
 parent-child process relationship (bsc#1156321).

CVE-2019-15239: Fixed a vulnerability where a local attacker could have
 triggered multiple use-after-free conditions resulted in privilege
 escalation (bsc#1156317).

CVE-2019-10220: Fixed an issue where samba servers could inject relative
 paths in directory entry lists (bsc#1153108).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 25 for SLE 12 SP3)' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_175-94_79-default", rpm:"kgraft-patch-4_4_175-94_79-default~7~2.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_175-94_79-default-debuginfo", rpm:"kgraft-patch-4_4_175-94_79-default-debuginfo~7~2.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_176-94_88-default", rpm:"kgraft-patch-4_4_176-94_88-default~6~2.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_176-94_88-default-debuginfo", rpm:"kgraft-patch-4_4_176-94_88-default-debuginfo~6~2.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_178-94_91-default", rpm:"kgraft-patch-4_4_178-94_91-default~6~2.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_178-94_91-default-debuginfo", rpm:"kgraft-patch-4_4_178-94_91-default-debuginfo~6~2.5", rls:"SLES12.0SP3"))) {
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
