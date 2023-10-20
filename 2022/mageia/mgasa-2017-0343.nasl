# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0343");
  script_cve_id("CVE-2017-1000251", "CVE-2017-11600", "CVE-2017-12134", "CVE-2017-14340");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-03 19:00:00 +0000 (Wed, 03 Jun 2020)");

  script_name("Mageia: Security Advisory (MGASA-2017-0343)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0343");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0343.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21709");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.9.44");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.9.45");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.9.46");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.9.47");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.9.48");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.9.49");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.9.50");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2017-0343 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-tmb update is based on upstream 4.9.50 and fixes at least the
following security issues:

net/xfrm/xfrm_policy.c in the Linux kernel through 4.12.3, when
CONFIG_XFRM_MIGRATE is enabled, does not ensure that the dir value of
xfrm_userpolicy_id is XFRM_POLICY_MAX or less, which allows local users
to cause a denial of service (out-of-bounds access) or possibly have
unspecified other impact via an XFRM_MSG_MIGRATE xfrm Netlink message
(CVE-2017-11600).

The xen_biovec_phys_mergeable function in drivers/xen/biomerge.c in Xen
might allow local OS guest users to corrupt block device data streams
and consequently obtain sensitive memory information, cause a denial of
service, or gain host OS privileges by leveraging incorrect block IO
merge-ability calculation (CVE-2017-12134 / XSA-229).

The XFS_IS_REALTIME_INODE macro in fs/xfs/xfs_linux.h in the Linux kernel
before 4.13.2 does not verify that a filesystem has a realtime device,
which allows local users to cause a denial of service (NULL pointer
dereference and OOPS) via vectors related to setting an RHINHERIT flag
on a directory (CVE-2017-14340).

The native Bluetooth stack in the Linux Kernel (BlueZ), starting at the
Linux kernel version 3.3-rc1 and up to and including 4.13.1, are vulnerable
to a stack overflow vulnerability in the processing of L2CAP configuration
responses resulting in Remote code execution in kernel space
(CVE-2017-1000251).

For other upstream fixes in this update, read the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~4.9.50~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-4.9.50-1.mga6", rpm:"kernel-tmb-desktop-4.9.50-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-4.9.50-1.mga6", rpm:"kernel-tmb-desktop-devel-4.9.50-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~4.9.50~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~4.9.50~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-4.9.50-1.mga6", rpm:"kernel-tmb-source-4.9.50-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~4.9.50~1.mga6", rls:"MAGEIA6"))) {
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
