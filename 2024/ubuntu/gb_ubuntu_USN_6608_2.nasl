# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6608.2");
  script_cve_id("CVE-2023-6606", "CVE-2023-6817", "CVE-2023-6931", "CVE-2023-6932", "CVE-2024-0193");
  script_tag(name:"creation_date", value:"2024-02-15 04:08:41 +0000 (Thu, 15 Feb 2024)");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-18 15:15:10 +0000 (Mon, 18 Dec 2023)");

  script_name("Ubuntu: Security Advisory (USN-6608-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6608-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6608-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-nvidia-6.2' package(s) announced via the USN-6608-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the CIFS network file system implementation in the
Linux kernel did not properly validate the server frame size in certain
situation, leading to an out-of-bounds read vulnerability. An attacker
could use this to construct a malicious CIFS image that, when operated on,
could cause a denial of service (system crash) or possibly expose sensitive
information. (CVE-2023-6606)

Xingyuan Mo discovered that the netfilter subsystem in the Linux kernel did
not properly handle inactive elements in its PIPAPO data structure, leading
to a use-after-free vulnerability. A local attacker could use this to cause
a denial of service (system crash) or possibly execute arbitrary code.
(CVE-2023-6817)

Budimir Markovic, Lucas De Marchi, and Pengfei Xu discovered that the perf
subsystem in the Linux kernel did not properly validate all event sizes
when attaching new events, leading to an out-of-bounds write vulnerability.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-6931)

It was discovered that the IGMP protocol implementation in the Linux kernel
contained a race condition, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-6932)

Kevin Rich discovered that the netfilter subsystem in the Linux kernel did
not properly check deactivated elements in certain situations, leading to a
use-after-free vulnerability. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2024-0193)");

  script_tag(name:"affected", value:"'linux-nvidia-6.2' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1015-nvidia", ver:"6.2.0-1015.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1015-nvidia-64k", ver:"6.2.0-1015.15", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-6.2", ver:"6.2.0.1015.17", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-64k-6.2", ver:"6.2.0.1015.17", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-64k-hwe-22.04", ver:"6.2.0.1015.17", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-hwe-22.04", ver:"6.2.0.1015.17", rls:"UBUNTU22.04 LTS"))) {
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
