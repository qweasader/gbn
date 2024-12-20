# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6871.1");
  script_cve_id("CVE-2023-52434", "CVE-2023-52447", "CVE-2023-52497", "CVE-2023-52620", "CVE-2023-52640", "CVE-2023-52641", "CVE-2023-52644", "CVE-2023-52645", "CVE-2023-52650", "CVE-2023-52652", "CVE-2023-52656", "CVE-2023-52662", "CVE-2023-6270", "CVE-2023-7042", "CVE-2024-0841", "CVE-2024-21823", "CVE-2024-22099", "CVE-2024-26583", "CVE-2024-26584", "CVE-2024-26585", "CVE-2024-26601", "CVE-2024-26603", "CVE-2024-26643", "CVE-2024-26651", "CVE-2024-26659", "CVE-2024-26688", "CVE-2024-26733", "CVE-2024-26735", "CVE-2024-26736", "CVE-2024-26737", "CVE-2024-26743", "CVE-2024-26744", "CVE-2024-26747", "CVE-2024-26748", "CVE-2024-26749", "CVE-2024-26750", "CVE-2024-26751", "CVE-2024-26752", "CVE-2024-26754", "CVE-2024-26763", "CVE-2024-26764", "CVE-2024-26766", "CVE-2024-26769", "CVE-2024-26771", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26774", "CVE-2024-26776", "CVE-2024-26777", "CVE-2024-26778", "CVE-2024-26779", "CVE-2024-26782", "CVE-2024-26787", "CVE-2024-26788", "CVE-2024-26790", "CVE-2024-26791", "CVE-2024-26792", "CVE-2024-26793", "CVE-2024-26795", "CVE-2024-26798", "CVE-2024-26801", "CVE-2024-26802", "CVE-2024-26803", "CVE-2024-26804", "CVE-2024-26805", "CVE-2024-26809", "CVE-2024-26816", "CVE-2024-26820", "CVE-2024-26833", "CVE-2024-26835", "CVE-2024-26838", "CVE-2024-26839", "CVE-2024-26840", "CVE-2024-26843", "CVE-2024-26845", "CVE-2024-26846", "CVE-2024-26848", "CVE-2024-26851", "CVE-2024-26852", "CVE-2024-26855", "CVE-2024-26856", "CVE-2024-26857", "CVE-2024-26859", "CVE-2024-26861", "CVE-2024-26862", "CVE-2024-26863", "CVE-2024-26870", "CVE-2024-26872", "CVE-2024-26874", "CVE-2024-26875", "CVE-2024-26877", "CVE-2024-26878", "CVE-2024-26879", "CVE-2024-26880", "CVE-2024-26881", "CVE-2024-26882", "CVE-2024-26883", "CVE-2024-26884", "CVE-2024-26885", "CVE-2024-26889", "CVE-2024-26891", "CVE-2024-26894", "CVE-2024-26895", "CVE-2024-26897", "CVE-2024-26898", "CVE-2024-26901", "CVE-2024-26903", "CVE-2024-26906", "CVE-2024-26907", "CVE-2024-26915", "CVE-2024-26924", "CVE-2024-27024", "CVE-2024-27028", "CVE-2024-27030", "CVE-2024-27034", "CVE-2024-27037", "CVE-2024-27038", "CVE-2024-27039", "CVE-2024-27043", "CVE-2024-27044", "CVE-2024-27045", "CVE-2024-27046", "CVE-2024-27047", "CVE-2024-27051", "CVE-2024-27052", "CVE-2024-27053", "CVE-2024-27054", "CVE-2024-27065", "CVE-2024-27073", "CVE-2024-27074", "CVE-2024-27075", "CVE-2024-27076", "CVE-2024-27077", "CVE-2024-27078", "CVE-2024-27388", "CVE-2024-27390", "CVE-2024-27403", "CVE-2024-27405", "CVE-2024-27410", "CVE-2024-27412", "CVE-2024-27413", "CVE-2024-27414", "CVE-2024-27415", "CVE-2024-27416", "CVE-2024-27417", "CVE-2024-27419", "CVE-2024-27431", "CVE-2024-27432", "CVE-2024-27436", "CVE-2024-35828", "CVE-2024-35829", "CVE-2024-35830", "CVE-2024-35844", "CVE-2024-35845");
  script_tag(name:"creation_date", value:"2024-07-04 04:08:00 +0000 (Thu, 04 Jul 2024)");
  script_version("2024-07-04T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-15 14:21:29 +0000 (Fri, 15 Mar 2024)");

  script_name("Ubuntu: Security Advisory (USN-6871-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6871-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6871-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-hwe-5.15' package(s) announced via the USN-6871-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the ATA over Ethernet (AoE) driver in the Linux
kernel contained a race condition, leading to a use-after-free
vulnerability. An attacker could use this to cause a denial of service or
possibly execute arbitrary code. (CVE-2023-6270)

It was discovered that the Atheros 802.11ac wireless driver did not
properly validate certain data structures, leading to a NULL pointer
dereference. An attacker could possibly use this to cause a denial of
service. (CVE-2023-7042)

It was discovered that the HugeTLB file system component of the Linux
Kernel contained a NULL pointer dereference vulnerability. A privileged
attacker could possibly use this to to cause a denial of service.
(CVE-2024-0841)

It was discovered that the Intel Data Streaming and Intel Analytics
Accelerator drivers in the Linux kernel allowed direct access to the
devices for unprivileged users and virtual machines. A local attacker could
use this to cause a denial of service. (CVE-2024-21823)

Yuxuan Hu discovered that the Bluetooth RFCOMM protocol driver in the Linux
Kernel contained a race condition, leading to a NULL pointer dereference.
An attacker could possibly use this to cause a denial of service (system
crash). (CVE-2024-22099)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM32 architecture,
 - RISC-V architecture,
 - x86 architecture,
 - ACPI drivers,
 - Block layer subsystem,
 - Clock framework and drivers,
 - CPU frequency scaling framework,
 - Cryptographic API,
 - DMA engine subsystem,
 - EFI core,
 - GPU drivers,
 - InfiniBand drivers,
 - IOMMU subsystem,
 - Multiple devices driver,
 - Media drivers,
 - MMC subsystem,
 - Network drivers,
 - NTB driver,
 - NVME drivers,
 - PCI subsystem,
 - MediaTek PM domains,
 - Power supply drivers,
 - SPI subsystem,
 - Media staging drivers,
 - TCM subsystem,
 - USB subsystem,
 - Framebuffer layer,
 - AFS file system,
 - File systems infrastructure,
 - BTRFS file system,
 - EROFS file system,
 - Ext4 file system,
 - F2FS file system,
 - Network file system client,
 - NTFS3 file system,
 - Diskquota system,
 - SMB network file system,
 - BPF subsystem,
 - Netfilter,
 - TLS protocol,
 - io_uring subsystem,
 - Bluetooth subsystem,
 - Memory management,
 - Ethernet bridge,
 - Networking core,
 - HSR network protocol,
 - IPv4 networking,
 - IPv6 networking,
 - L2TP protocol,
 - MAC80211 subsystem,
 - Multipath TCP,
 - Netlink,
 - NET/ROM layer,
 - Packet sockets,
 - RDS protocol,
 - Sun RPC protocol,
 - Unix domain sockets,
 - Wireless networking,
 - USB sound devices,
(CVE-2024-26901, CVE-2024-35844, CVE-2024-27024, CVE-2024-26835,
CVE-2024-26879, CVE-2024-26846, CVE-2024-35829, CVE-2024-26804,
CVE-2024-26802, CVE-2024-27039, CVE-2024-27075, CVE-2024-27076,
CVE-2024-26863, CVE-2024-27046, CVE-2024-26776, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-hwe-5.15' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-113-generic", ver:"5.15.0-113.123~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-113-generic-64k", ver:"5.15.0-113.123~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-113-generic-lpae", ver:"5.15.0-113.123~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-20.04", ver:"5.15.0.113.123~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-20.04", ver:"5.15.0.113.123~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-20.04", ver:"5.15.0.113.123~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04", ver:"5.15.0.113.123~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04b", ver:"5.15.0.113.123~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04c", ver:"5.15.0.113.123~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04d", ver:"5.15.0.113.123~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-20.04", ver:"5.15.0.113.123~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
