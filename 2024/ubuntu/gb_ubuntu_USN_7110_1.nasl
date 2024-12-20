# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7110.1");
  script_cve_id("CVE-2023-52528", "CVE-2024-26810", "CVE-2024-26812", "CVE-2024-27436", "CVE-2024-38602", "CVE-2024-38621", "CVE-2024-38627", "CVE-2024-38630", "CVE-2024-39487", "CVE-2024-39494", "CVE-2024-41097", "CVE-2024-42089", "CVE-2024-42223", "CVE-2024-42229", "CVE-2024-42271", "CVE-2024-42280", "CVE-2024-42284", "CVE-2024-43858", "CVE-2024-44940", "CVE-2024-46673");
  script_tag(name:"creation_date", value:"2024-11-15 04:08:07 +0000 (Fri, 15 Nov 2024)");
  script_version("2024-11-15T15:55:05+0000");
  script_tag(name:"last_modification", value:"2024-11-15 15:55:05 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-13 16:51:39 +0000 (Fri, 13 Sep 2024)");

  script_name("Ubuntu: Security Advisory (USN-7110-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7110-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7110-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-lts-xenial' package(s) announced via the USN-7110-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Cryptographic API,
 - HW tracing,
 - ISDN/mISDN subsystem,
 - Media drivers,
 - Network drivers,
 - SCSI drivers,
 - USB DSL drivers,
 - VFIO drivers,
 - Watchdog drivers,
 - JFS file system,
 - Amateur Radio drivers,
 - IPv4 networking,
 - IUCV driver,
 - TIPC protocol,
 - Integrity Measurement Architecture(IMA) framework,
 - SoC Audio for Freescale CPUs drivers,
 - USB sound devices,
(CVE-2024-42229, CVE-2024-27436, CVE-2024-42271, CVE-2024-46673,
CVE-2024-42284, CVE-2024-26810, CVE-2024-38602, CVE-2024-42280,
CVE-2024-43858, CVE-2024-42089, CVE-2024-44940, CVE-2024-42223,
CVE-2024-39487, CVE-2024-41097, CVE-2024-26812, CVE-2024-38627,
CVE-2024-38630, CVE-2023-52528, CVE-2024-39494, CVE-2024-38621)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-lts-xenial' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1137-aws", ver:"4.4.0-1137.143", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-260-generic", ver:"4.4.0-260.294~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-260-lowlatency", ver:"4.4.0-260.294~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1137.134", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1138-kvm", ver:"4.4.0-1138.148", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1175-aws", ver:"4.4.0-1175.190", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-260-generic", ver:"4.4.0-260.294", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-260-lowlatency", ver:"4.4.0-260.294", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1175.179", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.260.266", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.260.266", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.4.0.1138.135", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.260.266", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.260.266", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.4.0.260.266", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.260.266", rls:"UBUNTU16.04 LTS"))) {
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
