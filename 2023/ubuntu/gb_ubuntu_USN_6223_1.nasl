# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6223.1");
  script_cve_id("CVE-2023-1076", "CVE-2023-1077", "CVE-2023-1079", "CVE-2023-1670", "CVE-2023-1859", "CVE-2023-1998", "CVE-2023-25012", "CVE-2023-2985", "CVE-2023-35788");
  script_tag(name:"creation_date", value:"2023-07-13 04:09:42 +0000 (Thu, 13 Jul 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-23 21:19:19 +0000 (Fri, 23 Jun 2023)");

  script_name("Ubuntu: Security Advisory (USN-6223-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6223-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6223-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2023220");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2023577");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure-fde' package(s) announced via the USN-6223-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the TUN/TAP driver in the Linux kernel did not
properly initialize socket data. A local attacker could use this to cause a
denial of service (system crash). (CVE-2023-1076)

It was discovered that the Real-Time Scheduling Class implementation in the
Linux kernel contained a type confusion vulnerability in some situations. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2023-1077)

It was discovered that the ASUS HID driver in the Linux kernel did not
properly handle device removal, leading to a use-after-free vulnerability.
A local attacker with physical access could plug in a specially crafted USB
device to cause a denial of service (system crash). (CVE-2023-1079)

It was discovered that the Xircom PCMCIA network device driver in the Linux
kernel did not properly handle device removal events. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2023-1670)

It was discovered that a race condition existed in the Xen transport layer
implementation for the 9P file system protocol in the Linux kernel, leading
to a use-after-free vulnerability. A local attacker could use this to cause
a denial of service (guest crash) or expose sensitive information (guest
kernel memory). (CVE-2023-1859)

Jose Oliveira and Rodrigo Branco discovered that the Spectre Variant 2
mitigations with prctl syscall were insufficient in some situations. A
local attacker could possibly use this to expose sensitive information.
(CVE-2023-1998)

It was discovered that the BigBen Interactive Kids' gamepad driver in the
Linux kernel did not properly handle device removal, leading to a use-
after-free vulnerability. A local attacker with physical access could plug
in a specially crafted USB device to cause a denial of service (system
crash). (CVE-2023-25012)

It was discovered that a use-after-free vulnerability existed in the HFS+
file system implementation in the Linux kernel. A local attacker could
possibly use this to cause a denial of service (system crash).
(CVE-2023-2985)

Hangyu Hua discovered that the Flower classifier implementation in the
Linux kernel contained an out-of-bounds write vulnerability. An attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2023-35788, LP: #2023577)

It was discovered that for some Intel processors the INVLPG instruction
implementation did not properly flush global TLB entries when PCIDs are
enabled. An attacker could use this to expose sensitive information
(kernel memory) or possibly cause undesired behaviors. (LP: #2023220)");

  script_tag(name:"affected", value:"'linux-azure-fde' package(s) on Ubuntu 22.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1041-azure-fde", ver:"5.15.0-1041.48.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"5.15.0.1041.48.19", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde-lts-22.04", ver:"5.15.0.1041.48.19", rls:"UBUNTU22.04 LTS"))) {
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
