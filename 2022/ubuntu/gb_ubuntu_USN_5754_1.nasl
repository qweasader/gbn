# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5754.1");
  script_cve_id("CVE-2022-3524", "CVE-2022-3564", "CVE-2022-3565", "CVE-2022-3566", "CVE-2022-3567", "CVE-2022-3594", "CVE-2022-3621", "CVE-2022-43945");
  script_tag(name:"creation_date", value:"2022-12-02 04:10:50 +0000 (Fri, 02 Dec 2022)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 18:18:00 +0000 (Mon, 06 Feb 2023)");

  script_name("Ubuntu: Security Advisory (USN-5754-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.10");

  script_xref(name:"Advisory-ID", value:"USN-5754-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5754-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gcp, linux-ibm, linux-kvm, linux-lowlatency, linux-oracle, linux-raspi' package(s) announced via the USN-5754-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the NFSD implementation in the Linux kernel did not
properly handle some RPC messages, leading to a buffer overflow. A remote
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2022-43945)

It was discovered that a memory leak existed in the IPv6 implementation of
the Linux kernel. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2022-3524)

It was discovered that a race condition existed in the Bluetooth subsystem
in the Linux kernel, leading to a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2022-3564)

It was discovered that the ISDN implementation of the Linux kernel
contained a use-after-free vulnerability. A privileged user could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-3565)

It was discovered that the TCP implementation in the Linux kernel contained
a data race condition. An attacker could possibly use this to cause
undesired behaviors. (CVE-2022-3566)

It was discovered that the IPv6 implementation in the Linux kernel
contained a data race condition. An attacker could possibly use this to
cause undesired behaviors. (CVE-2022-3567)

It was discovered that the Realtek RTL8152 USB Ethernet adapter driver in
the Linux kernel did not properly handle certain error conditions. A local
attacker with physical access could plug in a specially crafted USB device
to cause a denial of service (memory exhaustion). (CVE-2022-3594)

It was discovered that a null pointer dereference existed in the NILFS2
file system implementation in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash). (CVE-2022-3621)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gcp, linux-ibm, linux-kvm, linux-lowlatency, linux-oracle, linux-raspi' package(s) on Ubuntu 22.10.");

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

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1009-raspi", ver:"5.19.0-1009.16", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1009-raspi-nolpae", ver:"5.19.0-1009.16", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1012-lowlatency", ver:"5.19.0-1012.13", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1012-lowlatency-64k", ver:"5.19.0-1012.13", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1013-gcp", ver:"5.19.0-1013.14", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1013-ibm", ver:"5.19.0-1013.14", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1013-kvm", ver:"5.19.0-1013.14", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1013-oracle", ver:"5.19.0-1013.14", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1014-aws", ver:"5.19.0-1014.15", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-26-generic", ver:"5.19.0-26.27", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-26-generic-64k", ver:"5.19.0-26.27", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-26-generic-lpae", ver:"5.19.0-26.27", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.19.0.1014.11", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.19.0.1013.10", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.19.0.26.23", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"5.19.0.26.23", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.19.0.26.23", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm", ver:"5.19.0.1013.10", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.19.0.1013.10", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.19.0.1012.9", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"5.19.0.1012.9", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.19.0.1013.10", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.19.0.1009.8", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.19.0.1009.8", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.19.0.26.23", rls:"UBUNTU22.10"))) {
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
