# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843960");
  script_cve_id("CVE-2018-14678", "CVE-2018-18021", "CVE-2018-19824", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2019-7308", "CVE-2019-8912", "CVE-2019-8980", "CVE-2019-9213");
  script_tag(name:"creation_date", value:"2019-04-03 06:40:49 +0000 (Wed, 03 Apr 2019)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 20:40:00 +0000 (Tue, 05 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-3931-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-3931-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3931-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws-hwe, linux-azure, linux-gcp, linux-hwe, linux-oracle' package(s) announced via the USN-3931-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3931-1 fixed vulnerabilities in the Linux kernel for Ubuntu 18.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 18.04 LTS for Ubuntu
16.04 LTS and for the Linux Azure kernel for Ubuntu 14.04 LTS.

M. Vefa Bicakci and Andy Lutomirski discovered that the kernel did not
properly set up all arguments to an error handler callback used when
running as a paravirtualized guest. An unprivileged attacker in a
paravirtualized guest VM could use this to cause a denial of service (guest
VM crash). (CVE-2018-14678)

It was discovered that the KVM implementation in the Linux kernel on ARM
64bit processors did not properly handle some ioctls. An attacker with the
privilege to create KVM-based virtual machines could use this to cause a
denial of service (host system crash) or execute arbitrary code in the
host. (CVE-2018-18021)

Mathias Payer and Hui Peng discovered a use-after-free vulnerability in the
Advanced Linux Sound Architecture (ALSA) subsystem. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2018-19824)

Shlomi Oberman, Yuli Shapiro, and Ran Menscher discovered an information
leak in the Bluetooth implementation of the Linux kernel. An attacker
within Bluetooth range could use this to expose sensitive information
(kernel memory). (CVE-2019-3459, CVE-2019-3460)

Jann Horn discovered that the KVM implementation in the Linux kernel
contained a use-after-free vulnerability. An attacker in a guest VM with
access to /dev/kvm could use this to cause a denial of service (guest VM
crash). (CVE-2019-6974)

Jim Mattson and Felix Wilhelm discovered a use-after-free vulnerability in
the KVM subsystem of the Linux kernel, when using nested virtual machines.
A local attacker in a guest VM could use this to cause a denial of service
(system crash) or possibly execute arbitrary code in the host system.
(CVE-2019-7221)

Felix Wilhelm discovered that an information leak vulnerability existed in
the KVM subsystem of the Linux kernel, when nested virtualization is used.
A local attacker could use this to expose sensitive information (host
system memory to a guest VM). (CVE-2019-7222)

Jann Horn discovered that the eBPF implementation in the Linux kernel was
insufficiently hardened against Spectre V1 attacks. A local attacker could
use this to expose sensitive information. (CVE-2019-7308)

It was discovered that a use-after-free vulnerability existed in the user-
space API for crypto (af_alg) implementation in the Linux kernel. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2019-8912)

It was discovered that the Linux kernel did not properly deallocate memory
when handling certain errors while reading files. A local attacker could
use this to cause a denial of service (excessive memory ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-aws-hwe, linux-azure, linux-gcp, linux-hwe, linux-oracle' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1041-azure", ver:"4.15.0-1041.45~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1041.28", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1010-oracle", ver:"4.15.0-1010.12~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1029-gcp", ver:"4.15.0-1029.31~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1035-aws", ver:"4.15.0-1035.37~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1041-azure", ver:"4.15.0-1041.45", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-47-generic", ver:"4.15.0-47.50~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-47-generic-lpae", ver:"4.15.0-47.50~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-47-lowlatency", ver:"4.15.0-47.50~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-hwe", ver:"4.15.0.1035.35", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1041.45", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.15.0.1029.43", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-16.04", ver:"4.15.0.47.68", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-16.04", ver:"4.15.0.47.68", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1029.43", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-16.04", ver:"4.15.0.47.68", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"4.15.0.47.68", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"4.15.0.1010.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-16.04", ver:"4.15.0.47.68", rls:"UBUNTU16.04 LTS"))) {
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
