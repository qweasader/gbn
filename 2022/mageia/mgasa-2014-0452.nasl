# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0452");
  script_cve_id("CVE-2014-3601", "CVE-2014-3631", "CVE-2014-7283", "CVE-2014-7284", "CVE-2014-7970", "CVE-2014-7975");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 18:15:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0452)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0452");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0452.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14011");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13098");
  script_xref(name:"URL", value:"http://kernelnewbies.org/Linux_3.13");
  script_xref(name:"URL", value:"http://kernelnewbies.org/Linux_3.14");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.1");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.2");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.3");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.4");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.5");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.6");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.7");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.8");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.9");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.10");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.11");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.12");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.13");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.14");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.15");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.16");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.17");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.18");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.19");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.20");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.21");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.22");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.23");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2014-0452 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-tmb update is based on upstream -longterm 3.14.23 and
fixes the following security issues:

The kvm_iommu_map_pages function in virt/kvm/iommu.c in the Linux
kernel through 3.16.1 miscalculates the number of pages during the
handling of a mapping failure, which allows guest OS users to (1)
cause a denial of service (host OS memory corruption) or possibly
have unspecified other impact by triggering a large gfn value or
(2) cause a denial of service (host OS memory consumption) by
triggering a small gfn value that leads to permanently pinned
pages (CVE-2014-3601).

The assoc_array_gc function in the associative-array implementation
in lib/assoc_array.c in the Linux kernel before 3.16.3 does not
properly implement garbage collection, which allows local users to
cause a denial of service (NULL pointer dereference and system
crash) or possibly have unspecified other impact via multiple
'keyctl newring' operations followed by a 'keyctl timeout'
operation (CVE-2014-3631).

The xfs_da3_fixhashpath function in fs/xfs/xfs_da_btree.c in the
xfs implementation in the Linux kernel before 3.14.2 does not properly
compare btree hash values, which allows local users to cause a denial
of service (filesystem corruption, and OOPS or panic) via operations
on directories that have hash collisions, as demonstrated by rmdir
operations (CVE-2014-7283).

The net_get_random_once implementation in net/core/utils.c in the
Linux kernel 3.13.x and 3.14.x before 3.14.5 on certain Intel processors
does not perform the intended slow-path operation to initialize random
seeds, which makes it easier for remote attackers to spoof or disrupt IP
communication by leveraging the predictability of TCP sequence numbers,
TCP and UDP port numbers, and IP ID values (CVE-2014-7284)

The pivot_root implementation in fs/namespace.c in the Linux kernel
through 3.17 does not properly interact with certain locations of
a chroot directory, which allows local users to cause a denial of
service (mount-tree loop) via . (dot) values in both arguments to
the pivot_root system call (CVE-2014-7970).

The do_umount function in fs/namespace.c in the Linux kernel
through 3.17 does not require the CAP_SYS_ADMIN capability for
do_remount_sb calls that change the root filesystem to read-only,
which allows local users to cause a denial of service (loss of
writability) by making certain unshare system calls, clearing the
/ MNT_LOCKED flag, and making an MNT_FORCE umount system call
(CVE-2014-7975).

Other fixes:
The X86_SYSFB config option has been disabled as it prevents
proper KMS setup on some systems (mga#13098)

BFS cpu scheduler has been updated to 0.454.

BFQ io scheduler has been added and set as default.

For other fixes included in this update, read the referenced
changelogs.");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~3.14.23~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-3.14.23-1.mga4", rpm:"kernel-tmb-desktop-3.14.23-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-3.14.23-1.mga4", rpm:"kernel-tmb-desktop-devel-3.14.23-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~3.14.23~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~3.14.23~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-3.14.23-1.mga4", rpm:"kernel-tmb-desktop586-3.14.23-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-devel-3.14.23-1.mga4", rpm:"kernel-tmb-desktop586-devel-3.14.23-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-devel-latest", rpm:"kernel-tmb-desktop586-devel-latest~3.14.23~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-latest", rpm:"kernel-tmb-desktop586-latest~3.14.23~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-3.14.23-1.mga4", rpm:"kernel-tmb-laptop-3.14.23-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-devel-3.14.23-1.mga4", rpm:"kernel-tmb-laptop-devel-3.14.23-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-devel-latest", rpm:"kernel-tmb-laptop-devel-latest~3.14.23~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-latest", rpm:"kernel-tmb-laptop-latest~3.14.23~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-3.14.23-1.mga4", rpm:"kernel-tmb-server-3.14.23-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-devel-3.14.23-1.mga4", rpm:"kernel-tmb-server-devel-3.14.23-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-devel-latest", rpm:"kernel-tmb-server-devel-latest~3.14.23~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-latest", rpm:"kernel-tmb-server-latest~3.14.23~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-3.14.23-1.mga4", rpm:"kernel-tmb-source-3.14.23-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~3.14.23~1.mga4", rls:"MAGEIA4"))) {
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
