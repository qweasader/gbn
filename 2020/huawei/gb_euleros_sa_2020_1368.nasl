# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1368");
  script_cve_id("CVE-2019-19447", "CVE-2019-19768", "CVE-2019-19807", "CVE-2020-2732");
  script_tag(name:"creation_date", value:"2020-04-01 13:55:19 +0000 (Wed, 01 Apr 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-30 16:50:45 +0000 (Thu, 30 Jan 2020)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2020-1368)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1368");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1368");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2020-1368 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel 5.0.21, mounting a crafted ext4 filesystem image, performing some operations, and unmounting can lead to a use-after-free in ext4_put_super in fs/ext4/super.c, related to dump_orphan_list in fs/ext4/super.c.(CVE-2019-19447)

A flaw was found in the way KVM hypervisor handled instruction emulation for the L2 guest when nested(=1) virtualization is enabled. In the instruction emulation, the L2 guest could trick the L0 hypervisor into accessing sensitive bits of the L1 hypervisor. An L2 guest could use this flaw to potentially access information of the L1 hypervisor.(CVE-2020-2732)

In the Linux kernel before 5.3.11, sound/core/timer.c has a use-after-free caused by erroneous code refactoring, aka CID-e7af6307a8a5. This is related to snd_timer_open and snd_timer_close_locked. The timeri variable was originally intended to be for a newly created timer instance, but was used for a different purpose after refactoring.(CVE-2019-19807)

In the Linux kernel 5.4.0-rc2, there is a use-after-free (read) in the __blk_add_trace function in kernel/trace/blktrace.c (which is used to fill out a blk_io_trace structure and place it in a per-cpu sub-buffer).(CVE-2019-19768)");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.36~vhulk1907.1.0.h702.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.36~vhulk1907.1.0.h702.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.36~vhulk1907.1.0.h702.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.36~vhulk1907.1.0.h702.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.36~vhulk1907.1.0.h702.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.36~vhulk1907.1.0.h702.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.36~vhulk1907.1.0.h702.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.36~vhulk1907.1.0.h702.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.36~vhulk1907.1.0.h702.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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
