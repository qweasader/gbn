# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5774.1");
  script_cve_id("CVE-2022-20422", "CVE-2022-2153", "CVE-2022-2978", "CVE-2022-3028", "CVE-2022-3239", "CVE-2022-3524", "CVE-2022-3564", "CVE-2022-3565", "CVE-2022-3566", "CVE-2022-3567", "CVE-2022-3594", "CVE-2022-3621", "CVE-2022-3635", "CVE-2022-36879", "CVE-2022-40768", "CVE-2022-42703");
  script_tag(name:"creation_date", value:"2022-12-13 04:10:37 +0000 (Tue, 13 Dec 2022)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 18:18:00 +0000 (Mon, 06 Feb 2023)");

  script_name("Ubuntu: Security Advisory (USN-5774-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5774-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5774-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-azure-4.15' package(s) announced via the USN-5774-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that the Linux kernel did not properly track memory
allocations for anonymous VMA mappings in some situations, leading to
potential data structure reuse. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2022-42703)

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

Abhishek Shah discovered a race condition in the PF_KEYv2 implementation in
the Linux kernel. A local attacker could use this to cause a denial of
service (system crash) or possibly expose sensitive information (kernel
memory). (CVE-2022-3028)

It was discovered that the video4linux driver for Empia based TV cards in
the Linux kernel did not properly perform reference counting in some
situations, leading to a use-after-free vulnerability. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2022-3239)

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
to cause a denial of service ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-azure, linux-azure-4.15' package(s) on Ubuntu 14.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1157-azure", ver:"4.15.0-1157.172~14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1157.124", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1157-azure", ver:"4.15.0-1157.172", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-18.04", ver:"4.15.0.1157.125", rls:"UBUNTU18.04 LTS"))) {
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
