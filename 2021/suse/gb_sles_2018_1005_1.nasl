# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1005.1");
  script_cve_id("CVE-2017-13166", "CVE-2018-1000004", "CVE-2018-1068", "CVE-2018-7566");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-18 15:53:08 +0000 (Wed, 18 Apr 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1005-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1005-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181005-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 20 for SLE 12 SP1)' package(s) announced via the SUSE-SU-2018:1005-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 3.12.74-60_64_57 fixes several issues.
The following security issues were fixed:
- CVE-2017-13166: An elevation of privilege vulnerability was fixed in the
 kernel v4l2 video driver. (bsc#1085447).
- CVE-2018-1068: A flaw was found in the Linux kernels implementation of
 32-bit syscall interface for bridging. This allowed a privileged user to
 arbitrarily write to a limited range of kernel memory (bsc#1085114).
- CVE-2018-1000004: A race condition vulnerability existed in the sound
 system, which could lead to a deadlock and denial of service condition
 (bsc#1076017)");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 20 for SLE 12 SP1)' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_57-default", rpm:"kgraft-patch-3_12_74-60_64_57-default~7~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_57-xen", rpm:"kgraft-patch-3_12_74-60_64_57-xen~7~2.1", rls:"SLES12.0SP1"))) {
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
