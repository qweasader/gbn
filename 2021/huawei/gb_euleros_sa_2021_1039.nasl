# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1039");
  script_cve_id("CVE-2015-7837", "CVE-2019-0145", "CVE-2019-0147", "CVE-2019-18282", "CVE-2019-18805", "CVE-2019-20934", "CVE-2020-0404", "CVE-2020-0431", "CVE-2020-0432", "CVE-2020-10690", "CVE-2020-12351", "CVE-2020-12352", "CVE-2020-14314", "CVE-2020-14351", "CVE-2020-14385", "CVE-2020-14386", "CVE-2020-14390", "CVE-2020-15436", "CVE-2020-15437", "CVE-2020-24394", "CVE-2020-24490", "CVE-2020-25212", "CVE-2020-25284", "CVE-2020-25285", "CVE-2020-25641", "CVE-2020-25643", "CVE-2020-25645", "CVE-2020-25656", "CVE-2020-25704", "CVE-2020-26088", "CVE-2020-27777", "CVE-2020-28915", "CVE-2020-28974", "CVE-2020-29370", "CVE-2020-29371", "CVE-2020-29374");
  script_tag(name:"creation_date", value:"2021-01-08 21:52:56 +0000 (Fri, 08 Jan 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-22 14:47:00 +0000 (Tue, 22 Jun 2021)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2021-1039)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1039");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1039");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2021-1039 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In uvc_scan_chain_forward of uvc_driver.c, there is a possible linked list corruption due to an unusual root cause. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-111893654References: Upstream kernel.(CVE-2020-0404)

A flaw was found in the Linux kernel in versions from 2.2.3 through 5.9.rc5. When changing screen size, an out-of-bounds memory write can occur leading to memory corruption or a denial of service. This highest threat from this vulnerability is to system availability.(CVE-2020-14390)

A TOCTOU mismatch in the NFS client code in the Linux kernel before 5.8.3 could be used by local attackers to corrupt memory or possibly have unspecified other impact because a size check is in fs4proc.c instead of fsfs4xdr.c, aka CID-b4487b935452.(CVE-2020-25212)

A flaw was found in the Linux kernel before 5.9-rc4. A failure of the file system metadata validator in XFS can cause an inode with a valid, user-creatable extended attribute to be flagged as corrupt. This can lead to the filesystem being shutdown, or otherwise rendered inaccessible until it is remounted, leading to a denial of service. The highest threat from this vulnerability is to system availability.(CVE-2020-14385)

In the Linux kernel before 5.7.8, fsfsd/vfs.c (in the NFS server) can set incorrect permissions on new filesystem objects when the filesystem lacks ACL support, aka CID-22cf8419f131. This occurs because the current umask is not considered.(CVE-2020-24394)

The rbd block device driver in drivers/block/rbd.c in the Linux kernel through 5.8.9 used incomplete permission checking for access to rbd devices, which could be leveraged by local attackers to map or unmap rbd block devices, aka CID-f44d04e696fe.(CVE-2020-25284)

An issue was discovered in net/ipv4/sysctl_net_ipv4.c in the Linux kernel before 5.0.11. There is a net/ipv4/tcp_input.c signed integer overflow in tcp_ack_update_rtt() when userspace writes a very large integer to /proc/sys et/ipv4/tcp_min_rtt_wlen, leading to a denial of service or possibly unspecified other impact, aka CID-19fad20d15a6.(CVE-2019-18805)

Insufficient input validation in i40e driver for Intel(R) Ethernet 700 Series Controllers versions before 7.0 may allow an authenticated user to potentially enable a denial of service via local access.(CVE-2019-0147)

Buffer overflow in i40e driver for Intel(R) Ethernet 700 Series Controllers versions before 7.0 may allow an authenticated user to potentially enable an escalation of privilege via local access.(CVE-2020-0145)

A race condition between hugetlb sysctl handlers in mm/hugetlb.c in the Linux kernel before 5.8.8 could be used by local attackers to corrupt memory, cause a NULL pointer dereference, or possibly have unspecified other impact, aka ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.36~vhulk1907.1.0.h906", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.36~vhulk1907.1.0.h906", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.36~vhulk1907.1.0.h906", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.36~vhulk1907.1.0.h906", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.36~vhulk1907.1.0.h906", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.36~vhulk1907.1.0.h906", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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
