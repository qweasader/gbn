# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5728.2");
  script_cve_id("CVE-2022-20422", "CVE-2022-2153", "CVE-2022-2978", "CVE-2022-29901", "CVE-2022-3028", "CVE-2022-3625", "CVE-2022-3635", "CVE-2022-40768", "CVE-2022-41222", "CVE-2022-42703", "CVE-2022-42719");
  script_tag(name:"creation_date", value:"2022-11-21 04:15:13 +0000 (Mon, 21 Nov 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-18 14:06:09 +0000 (Tue, 18 Oct 2022)");

  script_name("Ubuntu: Security Advisory (USN-5728-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5728-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5728-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure-fde, linux-gke, linux-gkeop, linux-raspi-5.4' package(s) announced via the USN-5728-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that the Linux kernel did not properly track memory
allocations for anonymous VMA mappings in some situations, leading to
potential data structure reuse. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2022-42703)

It was discovered that a race condition existed in the memory address space
accounting implementation in the Linux kernel, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-41222)

It was discovered that a race condition existed in the instruction emulator
of the Linux kernel on Arm 64-bit systems. A local attacker could use this
to cause a denial of service (system crash). (CVE-2022-20422)

It was discovered that the KVM implementation in the Linux kernel did not
properly handle virtual CPUs without APICs in certain situations. A local
attacker could possibly use this to cause a denial of service (host system
crash). (CVE-2022-2153)

Hao Sun and Jiacheng Xu discovered that the NILFS file system
implementation in the Linux kernel contained a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-2978)

Johannes Wikner and Kaveh Razavi discovered that for some Intel x86-64
processors, the Linux kernel's protections against speculative branch
target injection attacks were insufficient in some circumstances. A local
attacker could possibly use this to expose sensitive information.
(CVE-2022-29901)

Abhishek Shah discovered a race condition in the PF_KEYv2 implementation in
the Linux kernel. A local attacker could use this to cause a denial of
service (system crash) or possibly expose sensitive information (kernel
memory). (CVE-2022-3028)

It was discovered that the Netlink device interface implementation in the
Linux kernel did not properly handle certain error conditions, leading to a
use-after-free vulnerability with some network device drivers. A local
attacker with admin access to the network device could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2022-3625)

It was discovered that the IDT 77252 ATM PCI device driver in the Linux
kernel did not properly remove any pending timers during device exit,
resulting in a use-after-free vulnerability. A local attacker could
possibly use this to cause a denial of service (system crash) or execute
arbitrary code. (CVE-2022-3635)

Xingyuan Mo and Gengjia Chen discovered that the Promise SuperTrak EX
storage controller driver in the Linux kernel did not properly handle
certain structures. A local attacker could potentially use this to expose
sensitive information (kernel memory). (CVE-2022-40768)

Sonke Huster discovered that a use-after-free vulnerability existed in the
WiFi ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-azure-fde, linux-gke, linux-gkeop, linux-raspi-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1074-raspi", ver:"5.4.0-1074.85~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-hwe-18.04", ver:"5.4.0.1074.73", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1057-gkeop", ver:"5.4.0-1057.61", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1087-gke", ver:"5.4.0-1087.94", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1095-azure-fde", ver:"5.4.0-1095.101+cvm1.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"5.4.0.1095.101+cvm1.33", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.4.0.1087.94", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.4", ver:"5.4.0.1087.94", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop", ver:"5.4.0.1057.57", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.4", ver:"5.4.0.1057.57", rls:"UBUNTU20.04 LTS"))) {
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
