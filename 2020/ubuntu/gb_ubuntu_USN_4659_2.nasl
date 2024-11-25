# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844758");
  script_cve_id("CVE-2020-0423", "CVE-2020-10135", "CVE-2020-14351", "CVE-2020-25705", "CVE-2020-27152", "CVE-2020-28915", "CVE-2020-4788");
  script_tag(name:"creation_date", value:"2020-12-14 04:00:31 +0000 (Mon, 14 Dec 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-08 16:05:31 +0000 (Tue, 08 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-4659-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.10");

  script_xref(name:"Advisory-ID", value:"USN-4659-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4659-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1907262");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-oracle, linux-raspi' package(s) announced via the USN-4659-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4659-1 fixed vulnerabilities in the Linux kernel. Unfortunately,
that update introduced a regression in the software raid10 driver
when used with fstrim that could lead to data corruption. This update
fixes the problem.

Original advisory details:

It was discovered that a race condition existed in the binder IPC
implementation in the Linux kernel, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2020-0423)

Daniele Antonioli, Nils Ole Tippenhauer, and Kasper Rasmussen discovered
that legacy pairing and secure-connections pairing authentication in the
Bluetooth protocol could allow an unauthenticated user to complete
authentication without pairing credentials via adjacent access. A
physically proximate attacker could use this to impersonate a previously
paired Bluetooth device. (CVE-2020-10135)

It was discovered that a race condition existed in the perf subsystem of
the Linux kernel, leading to a use-after-free vulnerability. An attacker
with access to the perf subsystem could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2020-14351)

Keyu Man discovered that the ICMP global rate limiter in the Linux kernel
could be used to assist in scanning open UDP ports. A remote attacker could
use to facilitate attacks on UDP based services that depend on source port
randomization. (CVE-2020-25705)

It was discovered that the KVM hypervisor in the Linux kernel did not
properly handle interrupts in certain situations. A local attacker in a
guest VM could possibly use this to cause a denial of service (host system
crash). (CVE-2020-27152)

It was discovered that the framebuffer implementation in the Linux kernel
did not properly perform range checks in certain situations. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2020-28915)

It was discovered that Power 9 processors could be coerced to expose
information from the L1 cache in certain situations. A local attacker could
use this to expose sensitive information. (CVE-2020-4788)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-oracle, linux-raspi' package(s) on Ubuntu 20.10.");

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

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1010-raspi", ver:"5.8.0-1010.13", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1010-raspi-nolpae", ver:"5.8.0-1010.13", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1013-kvm", ver:"5.8.0-1013.14", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1013-oracle", ver:"5.8.0-1013.13", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1014-gcp", ver:"5.8.0-1014.14", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1015-azure", ver:"5.8.0-1015.16", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1016-aws", ver:"5.8.0-1016.17", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-33-generic", ver:"5.8.0-33.36", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-33-generic-64k", ver:"5.8.0-33.36", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-33-generic-lpae", ver:"5.8.0-33.36", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-33-lowlatency", ver:"5.8.0-33.36", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.8.0.1016.18", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.8.0.1015.15", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.8.0.1014.14", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.8.0.33.38", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"5.8.0.33.38", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.8.0.33.38", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.8.0.1014.14", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.8.0.1013.15", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.8.0.33.38", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04", ver:"5.8.0.33.38", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.8.0.1013.13", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.8.0.1010.13", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.8.0.1010.13", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.8.0.33.38", rls:"UBUNTU20.10"))) {
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
