# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844203");
  script_cve_id("CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14821", "CVE-2019-15504", "CVE-2019-15505", "CVE-2019-15902", "CVE-2019-16714", "CVE-2019-2181");
  script_tag(name:"creation_date", value:"2019-10-18 02:00:55 +0000 (Fri, 18 Oct 2019)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-16 14:09:00 +0000 (Wed, 16 Nov 2022)");

  script_name("Ubuntu: Security Advisory (USN-4157-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU19\.04");

  script_xref(name:"Advisory-ID", value:"USN-4157-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4157-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-raspi2, linux-snapdragon' package(s) announced via the USN-4157-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Wen Huang discovered that the Marvell Wi-Fi device driver in the Linux
kernel did not properly perform bounds checking, leading to a heap
overflow. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-14814,
CVE-2019-14815, CVE-2019-14816)

Matt Delco discovered that the KVM hypervisor implementation in the Linux
kernel did not properly perform bounds checking when handling coalesced
MMIO write operations. A local attacker with write access to /dev/kvm could
use this to cause a denial of service (system crash). (CVE-2019-14821)

Hui Peng and Mathias Payer discovered that the 91x Wi-Fi driver in the
Linux kernel did not properly handle error conditions on initialization,
leading to a double-free vulnerability. A physically proximate attacker
could use this to cause a denial of service (system crash).
(CVE-2019-15504)

It was discovered that the Technisat DVB-S/S2 USB device driver in the
Linux kernel contained a buffer overread. A physically proximate attacker
could use this to cause a denial of service (system crash) or possibly
expose sensitive information. (CVE-2019-15505)

Brad Spengler discovered that a Spectre mitigation was improperly
implemented in the ptrace subsystem of the Linux kernel. A local attacker
could possibly use this to expose sensitive information. (CVE-2019-15902)

It was discovered that the IPv6 RDS implementation in the Linux kernel did
not properly initialize fields in a data structure returned to user space.
A local attacker could use this to expose sensitive information (kernel
memory). Please note that the RDS protocol is disabled via blocklist in
Ubuntu by default. (CVE-2019-16714)

It was discovered that an integer overflow existed in the Binder
implementation of the Linux kernel, leading to a buffer overflow. A local
attacker could use this to escalate privileges. (CVE-2019-2181)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-raspi2, linux-snapdragon' package(s) on Ubuntu 19.04.");

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

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1019-aws", ver:"5.0.0-1019.21", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1020-kvm", ver:"5.0.0-1020.21", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1020-raspi2", ver:"5.0.0-1020.20", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1021-gcp", ver:"5.0.0-1021.21", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1023-azure", ver:"5.0.0-1023.24", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1024-snapdragon", ver:"5.0.0-1024.25", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-32-generic", ver:"5.0.0-32.34", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-32-generic-lpae", ver:"5.0.0-32.34", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-32-lowlatency", ver:"5.0.0-32.34", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.0.0.1019.20", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.0.0.1023.22", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.0.0.1021.47", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.0.0.32.33", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.0.0.32.33", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.0.0.1021.47", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.0.0.1020.20", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.0.0.32.33", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"5.0.0.1020.17", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"5.0.0.1024.17", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.0.0.32.33", rls:"UBUNTU19.04"))) {
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
