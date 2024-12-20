# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6092.1");
  script_cve_id("CVE-2023-0459", "CVE-2023-1118", "CVE-2023-1513", "CVE-2023-2162", "CVE-2023-32269");
  script_tag(name:"creation_date", value:"2023-05-19 04:09:46 +0000 (Fri, 19 May 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-10 04:59:09 +0000 (Fri, 10 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-6092-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6092-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6092-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-azure-4.15' package(s) announced via the USN-6092-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jordy Zomer and Alexandra Sandulescu discovered that the Linux kernel did
not properly implement speculative execution barriers in usercopy functions
in certain situations. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2023-0459)

Xingyuan Mo discovered that the x86 KVM implementation in the Linux kernel
did not properly initialize some data structures. A local attacker could
use this to expose sensitive information (kernel memory). (CVE-2023-1513)

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

  script_tag(name:"affected", value:"'linux-azure, linux-azure-4.15' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1165-azure", ver:"4.15.0-1165.180~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1165.131", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1165-azure", ver:"4.15.0-1165.180~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1165.149", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1165-azure", ver:"4.15.0-1165.180", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-18.04", ver:"4.15.0.1165.133", rls:"UBUNTU18.04 LTS"))) {
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
