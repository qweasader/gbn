# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1308");
  script_cve_id("CVE-2021-0920", "CVE-2021-0941", "CVE-2021-20321", "CVE-2021-33098", "CVE-2021-3428", "CVE-2021-39656", "CVE-2021-4002", "CVE-2021-4037", "CVE-2021-4083", "CVE-2021-4135");
  script_tag(name:"creation_date", value:"2022-03-02 14:40:28 +0000 (Wed, 02 Mar 2022)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 16:21:40 +0000 (Mon, 29 Aug 2022)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2022-1308)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1308");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2022-1308");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2022-1308 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A read-after-free memory flaw was found in the Linux kernel s garbage collection for Unix domain socket file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race condition. This flaw allows a local user to crash the system or escalate their privileges on the system.(CVE-2021-4083)

A flaw was found in the Linux kernel. A denial of service problem is identified if an extent tree is corrupted in a crafted ext4 filesystem in fs/ext4/extents.c in ext4_es_cache_extent. Fabricating an integer overflow, A local attacker with a special user privilege may cause a system crash problem which can lead to an availability threat.(CVE-2021-3428)

A flaw memory leak in the Linux kernel's eBPF for the Simulated networking device driver in the way user uses BPF for the device such that function nsim_map_alloc_elem being called. A local user could use this flaw to get unauthorized access to some data.(CVE-2021-4135)

In bpf_skb_change_head of filter.c, there is a possible out of bounds read due to a use after free. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.(CVE-2021-0941)

In __configfs_open_file of file.c, there is a possible use-after-free due to improper locking. This could lead to local escalation of privilege in the kernel with System execution privileges needed. User interaction is not needed for exploitation.(CVE-2021-39656)

A race condition accessing file object in the Linux kernel OverlayFS subsystem was found in the way users do rename in specific way with OverlayFS. A local user could use this flaw to crash the system.(CVE-2021-20321)

A vulnerability was found in the fs/inode.c:inode_init_owner() function logic of the LInux kernel that allows local users to create files for the XFS file-system with an unintended group ownership and with group execution and SGID permission bits set, in a scenario where a directory is SGID and belongs to a certain group and is writable by a user who is not a member of this group. This can lead to excessive permissions granted in case when they should not. (CVE-2021-4037)

Improper input validation in the Intel(R) Ethernet ixgbe driver for Linux before version 3.17.3 may allow an authenticated user to potentially enable denial of service via local access.(CVE-2021-33098)

In unix_scm_to_skb of af_unix.c, there is a possible use after free bug due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.(CVE-2021-0920)

A memory leak flaw in the Linux kernel's hugetlbfs memory usage was found in the way the user maps some regions of memory twice using shmget() which are aligned to PUD alignment with the fault of some of the memory pages. A local user could use this flaw to get unauthorized access to some data.(CVE-2021-4002)");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROS-2.0SP9") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2103.1.0.h640.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2103.1.0.h640.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2103.1.0.h640.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2103.1.0.h640.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
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
