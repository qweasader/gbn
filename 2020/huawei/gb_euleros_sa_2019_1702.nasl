# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1702");
  script_cve_id("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-11833", "CVE-2019-12382");
  script_tag(name:"creation_date", value:"2020-01-23 12:20:21 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-10-08T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-10-08 05:05:46 +0000 (Tue, 08 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-20 18:10:57 +0000 (Thu, 20 Jun 2019)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1702)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1702");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1702");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1702 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An excessive resource consumption flaw was found in the way the Linux kernel's networking subsystem processed TCP segments. If the Maximum Segment Size (MSS) of a TCP connection was set to low values, such as 48 bytes, it can leave as little as 8 bytes for the user data, which significantly increases the Linux kernel's resource (CPU, Memory, and Bandwidth) utilization. A remote attacker could use this flaw to cause a denial of service (DoS) by repeatedly sending network traffic on a TCP connection with low TCP MSS.(CVE-2019-11479)

An excessive resource consumption flaw was found in the way the Linux kernel's networking subsystem processed TCP Selective Acknowledgment (SACK) segments. While processing SACK segments, the Linux kernel's socket buffer (SKB) data structure becomes fragmented, which leads to increased resource utilization to traverse and process these fragments as further SACK segments are received on the same TCP connection. A remote attacker could use this flaw to cause a denial of service (DoS) by sending a crafted sequence of SACK segments on a TCP connection.(CVE-2019-11478)

An integer overflow flaw was found in the way the Linux kernel's networking subsystem processed TCP Selective Acknowledgment (SACK) segments. While processing SACK segments, the Linux kernel's socket buffer (SKB) data structure becomes fragmented. Each fragment is about TCP maximum segment size (MSS) bytes. To efficiently process SACK blocks, the Linux kernel merges multiple fragmented SKBs into one, potentially overflowing the variable holding the number of segments. A remote attacker could use this flaw to crash the Linux kernel by sending a crafted sequence of SACK segments on a TCP connection with small value of TCP MSS, resulting in a denial of service (DoS).(CVE-2019-11477)

A flaw was found in the Linux kernel's implementation of ext4 extent management. The kernel doesn't correctly initialize memory regions in the extent tree block which may be exported to a local user to obtain sensitive information by reading empty/uninitialized data from the filesystem.(CVE-2019-11833)

** DISPUTED ** An issue was discovered in drm_load_edid_firmware in drivers/gpu/drm/drm_edid_load.c in the Linux kernel through 5.1.5. There is an unchecked kstrdup of fwstr, which might allow an attacker to cause a denial of service (NULL pointer dereference and system crash). NOTE: The vendor disputes this issue as not being a vulnerability because kstrdup() returning NULL is handled sufficiently and there is no chance for a NULL pointer dereference.(CVE-2019-12382)

Note1: kernel-4.19.36-vhulk1907.1.0.h529 and earlier versions in EulerOS Virtualization for ARM 64 3.0.2.0 return incorrect time information when executing the uname -a command.

Note2: The kernel version number naming format has been changed after 4.19.36-1.2.184.aarch64, the new version format is 4.19.36-vhulk1907.1.0.hxxx.aarch64, which may lead to false positives of this security advisory.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod", value:"30");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.36~1.2.184", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.36~1.2.184", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.36~1.2.184", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.36~1.2.184", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.36~1.2.184", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.36~1.2.184", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.36~1.2.184", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.36~1.2.184", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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
