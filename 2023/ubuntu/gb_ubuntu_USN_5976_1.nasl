# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5976.1");
  script_cve_id("CVE-2022-2196", "CVE-2022-3061", "CVE-2022-3628", "CVE-2022-36280", "CVE-2022-3646", "CVE-2022-3649", "CVE-2022-41850", "CVE-2023-0394", "CVE-2023-0461");
  script_tag(name:"creation_date", value:"2023-03-28 04:11:11 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-13 14:12:00 +0000 (Fri, 13 Jan 2023)");

  script_name("Ubuntu: Security Advisory (USN-5976-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5976-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5976-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-5.14, linux-oem-5.17' package(s) announced via the USN-5976-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Upper Level Protocol (ULP) subsystem in the
Linux kernel did not properly handle sockets entering the LISTEN state in
certain protocols, leading to a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-0461)

It was discovered that the KVM VMX implementation in the Linux kernel did
not properly handle indirect branch prediction isolation between L1 and L2
VMs. An attacker in a guest VM could use this to expose sensitive
information from the host OS or other guest VMs. (CVE-2022-2196)

It was discovered that the Intel 740 frame buffer driver in the Linux
kernel contained a divide by zero vulnerability. A local attacker could use
this to cause a denial of service (system crash). (CVE-2022-3061)

It was discovered that the Broadcom FullMAC USB WiFi driver in the Linux
kernel did not properly perform bounds checking in some situations. A
physically proximate attacker could use this to craft a malicious USB
device that when inserted, could cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2022-3628)

Ziming Zhang discovered that the VMware Virtual GPU DRM driver in the Linux
kernel contained an out-of-bounds write vulnerability. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2022-36280)

It was discovered that the NILFS2 file system implementation in the Linux
kernel did not properly deallocate memory in certain error conditions. An
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2022-3646)

Khalid Masum discovered that the NILFS2 file system implementation in the
Linux kernel did not properly handle certain error conditions, leading to a
use-after-free vulnerability. A local attacker could use this to cause a
denial of service or possibly execute arbitrary code. (CVE-2022-3649)

It was discovered that a race condition existed in the Roccat HID driver in
the Linux kernel, leading to a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2022-41850)

Kyle Zeng discovered that the IPv6 implementation in the Linux kernel
contained a NULL pointer dereference vulnerability in certain situations. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2023-0394)");

  script_tag(name:"affected", value:"'linux-oem-5.14, linux-oem-5.17' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.14.0-1059-oem", ver:"5.14.0-1059.67", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04", ver:"5.14.0.1059.57", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04b", ver:"5.14.0.1059.57", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04c", ver:"5.14.0.1059.57", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04d", ver:"5.14.0.1059.57", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.17.0-1029-oem", ver:"5.17.0-1029.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04", ver:"5.17.0.1029.27", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04a", ver:"5.17.0.1029.27", rls:"UBUNTU22.04 LTS"))) {
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
