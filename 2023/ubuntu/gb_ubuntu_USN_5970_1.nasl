# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5970.1");
  script_cve_id("CVE-2022-2196", "CVE-2022-42328", "CVE-2022-42329", "CVE-2022-4382", "CVE-2023-0045", "CVE-2023-0266", "CVE-2023-0469", "CVE-2023-1195", "CVE-2023-23559");
  script_tag(name:"creation_date", value:"2023-03-24 04:11:00 +0000 (Fri, 24 Mar 2023)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-13 14:12:08 +0000 (Fri, 13 Jan 2023)");

  script_name("Ubuntu: Security Advisory (USN-5970-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.10");

  script_xref(name:"Advisory-ID", value:"USN-5970-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5970-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-ibm, linux-kvm, linux-lowlatency, linux-oracle, linux-raspi' package(s) announced via the USN-5970-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the KVM VMX implementation in the Linux kernel did
not properly handle indirect branch prediction isolation between L1 and L2
VMs. An attacker in a guest VM could use this to expose sensitive
information from the host OS or other guest VMs. (CVE-2022-2196)

It was discovered that a race condition existed in the Xen network backend
driver in the Linux kernel when handling dropped packets in certain
circumstances. An attacker could use this to cause a denial of service
(kernel deadlock). (CVE-2022-42328, CVE-2022-42329)

Gerald Lee discovered that the USB Gadget file system implementation in the
Linux kernel contained a race condition, leading to a use-after-free
vulnerability in some situations. A local attacker could use this to cause
a denial of service (system crash) or possibly execute arbitrary code.
(CVE-2022-4382)

Jose Oliveira and Rodrigo Branco discovered that the prctl syscall
implementation in the Linux kernel did not properly protect against
indirect branch prediction attacks in some situations. A local attacker
could possibly use this to expose sensitive information. (CVE-2023-0045)

It was discovered that a use-after-free vulnerability existed in the
Advanced Linux Sound Architecture (ALSA) subsystem. A local attacker could
use this to cause a denial of service (system crash). (CVE-2023-0266)

It was discovered that the io_uring subsystem in the Linux kernel contained
a use-after-free vulnerability. A local attacker could possibly use this to
cause a denial of service (system crash) or execute arbitrary code.
(CVE-2023-0469)

It was discovered that the CIFS network file system implementation in the
Linux kernel contained a user-after-free vulnerability. A local attacker
could possibly use this to cause a denial of service (system crash) or
execute arbitrary code. (CVE-2023-1195)

It was discovered that the RNDIS USB driver in the Linux kernel contained
an integer overflow vulnerability. A local attacker with physical access
could plug in a malicious USB device to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2023-23559)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-ibm, linux-kvm, linux-lowlatency, linux-oracle, linux-raspi' package(s) on Ubuntu 22.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1015-raspi", ver:"5.19.0-1015.22", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1015-raspi-nolpae", ver:"5.19.0-1015.22", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1019-gcp", ver:"5.19.0-1019.21", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1019-ibm", ver:"5.19.0-1019.21", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1019-oracle", ver:"5.19.0-1019.22", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1020-kvm", ver:"5.19.0-1020.21", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1021-lowlatency", ver:"5.19.0-1021.22", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1021-lowlatency-64k", ver:"5.19.0-1021.22", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1022-aws", ver:"5.19.0-1022.23", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1022-azure", ver:"5.19.0-1022.23", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-38-generic", ver:"5.19.0-38.39", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-38-generic-64k", ver:"5.19.0-38.39", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-38-generic-lpae", ver:"5.19.0-38.39", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.19.0.1022.19", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.19.0.1022.18", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.19.0.1019.16", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.19.0.38.34", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"5.19.0.38.34", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.19.0.38.34", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm", ver:"5.19.0.1019.16", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.19.0.1020.17", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.19.0.1021.17", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"5.19.0.1021.17", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.19.0.1019.16", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.19.0.1015.14", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.19.0.1015.14", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.19.0.38.34", rls:"UBUNTU22.10"))) {
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
