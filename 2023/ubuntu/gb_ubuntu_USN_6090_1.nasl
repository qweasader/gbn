# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6090.1");
  script_cve_id("CVE-2022-27672", "CVE-2022-3707", "CVE-2023-0459", "CVE-2023-1075", "CVE-2023-1078", "CVE-2023-1118", "CVE-2023-1513", "CVE-2023-20938", "CVE-2023-2162", "CVE-2023-32269");
  script_tag(name:"creation_date", value:"2023-05-19 04:09:46 +0000 (Fri, 19 May 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-06 19:32:27 +0000 (Mon, 06 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-6090-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6090-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6090-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp, linux-gcp-5.15, linux-gke, linux-gke-5.15, linux-gkeop, linux-oracle-5.15' package(s) announced via the USN-6090-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that some AMD x86-64 processors with SMT enabled could
speculatively execute instructions using a return address from a sibling
thread. A local attacker could possibly use this to expose sensitive
information. (CVE-2022-27672)

Zheng Wang discovered that the Intel i915 graphics driver in the Linux
kernel did not properly handle certain error conditions, leading to a
double-free. A local attacker could possibly use this to cause a denial of
service (system crash). (CVE-2022-3707)

Jordy Zomer and Alexandra Sandulescu discovered that the Linux kernel did
not properly implement speculative execution barriers in usercopy functions
in certain situations. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2023-0459)

It was discovered that the TLS subsystem in the Linux kernel contained a
type confusion vulnerability in some situations. A local attacker could use
this to cause a denial of service (system crash) or possibly expose
sensitive information. (CVE-2023-1075)

It was discovered that the Reliable Datagram Sockets (RDS) protocol
implementation in the Linux kernel contained a type confusion vulnerability
in some situations. An attacker could use this to cause a denial of service
(system crash). (CVE-2023-1078)

Xingyuan Mo discovered that the x86 KVM implementation in the Linux kernel
did not properly initialize some data structures. A local attacker could
use this to expose sensitive information (kernel memory). (CVE-2023-1513)

It was discovered that the Android Binder IPC subsystem in the Linux kernel
did not properly validate inputs in some situations, leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2023-20938)

It was discovered that a use-after-free vulnerability existed in the iSCSI
TCP implementation in the Linux kernel. A local attacker could possibly use
this to cause a denial of service (system crash). (CVE-2023-2162)

It was discovered that the NET/ROM protocol implementation in the Linux
kernel contained a race condition in some situations, leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2023-32269)

Duoming Zhou discovered that a race condition existed in the infrared
receiver/transceiver driver in the Linux kernel, leading to a use-after-
free vulnerability. A privileged attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2023-1118)");

  script_tag(name:"affected", value:"'linux-gcp, linux-gcp-5.15, linux-gke, linux-gke-5.15, linux-gkeop, linux-oracle-5.15' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1033-gke", ver:"5.15.0-1033.38~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1034-gcp", ver:"5.15.0-1034.42~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1035-oracle", ver:"5.15.0-1035.41~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.15.0.1034.42~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.15", ver:"5.15.0.1033.38~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.15.0.1035.41~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1020-gkeop", ver:"5.15.0-1020.25", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1033-gke", ver:"5.15.0-1033.38", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1034-gcp", ver:"5.15.0-1034.42+1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-22.04", ver:"5.15.0.1034.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.15.0.1033.32", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.15", ver:"5.15.0.1033.32", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop", ver:"5.15.0.1020.19", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.15", ver:"5.15.0.1020.19", rls:"UBUNTU22.04 LTS"))) {
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
