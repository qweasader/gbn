# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844901");
  script_cve_id("CVE-2021-29154", "CVE-2021-3492", "CVE-2021-3493");
  script_tag(name:"creation_date", value:"2021-04-16 03:00:21 +0000 (Fri, 16 Apr 2021)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-31 17:15:00 +0000 (Mon, 31 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-4917-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|20\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4917-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4917-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-gke-5.3, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe, linux-hwe-5.4, linux-hwe-5.8, linux-kvm, linux-oem-5.10, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi2-5.3, linux-raspi-5.4' package(s) announced via the USN-4917-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the overlayfs implementation in the Linux kernel did
not properly validate the application of file system capabilities with
respect to user namespaces. A local attacker could use this to gain
elevated privileges. (CVE-2021-3493)

Vincent Dehors discovered that the shiftfs file system in the Ubuntu Linux
kernel did not properly handle faults in copy_from_user() when passing
through ioctls to an underlying file system. A local attacker could use
this to cause a denial of service (memory exhaustion) or execute arbitrary
code. (CVE-2021-3492)

Piotr Krysiuk discovered that the BPF JIT compiler for x86 in the Linux
kernel did not properly validate computation of branch displacements in
some situations. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2021-29154)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-gke-5.3, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe, linux-hwe-5.4, linux-hwe-5.8, linux-kvm, linux-oem-5.10, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi2-5.3, linux-raspi-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-1039-raspi2", ver:"5.3.0-1039.41", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-1042-gke", ver:"5.3.0-1042.45", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-73-generic", ver:"5.3.0-73.69", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-73-lowlatency", ver:"5.3.0-73.69", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1014-gkeop", ver:"5.4.0-1014.15~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1034-raspi", ver:"5.4.0-1034.37~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1042-gcp", ver:"5.4.0-1042.45~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1042-gke", ver:"5.4.0-1042.44~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1043-oracle", ver:"5.4.0-1043.46~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1045-aws", ver:"5.4.0-1045.47~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1046-azure", ver:"5.4.0-1046.48~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-72-generic", ver:"5.4.0-72.80~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-72-generic-lpae", ver:"5.4.0-72.80~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-72-lowlatency", ver:"5.4.0-72.80~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.4.0.1045.27", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.4.0.1046.25", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.4.0.1042.29", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-18.04", ver:"5.4.0.72.80~18.04.65", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-18.04", ver:"5.4.0.72.80~18.04.65", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.3", ver:"5.3.0.1042.25", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.4", ver:"5.4.0.1042.44~18.04.8", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.3", ver:"5.3.0.73.130", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.4", ver:"5.4.0.1014.15~18.04.15", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-18.04", ver:"5.4.0.72.80~18.04.65", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"5.4.0.72.80~18.04.65", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-osp1", ver:"5.4.0.72.80~18.04.65", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.4.0.1043.46~18.04.25", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-hwe-18.04", ver:"5.4.0.1034.36", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2-hwe-18.04", ver:"5.3.0.1039.28", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon-hwe-18.04", ver:"5.4.0.72.80~18.04.65", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-18.04", ver:"5.4.0.72.80~18.04.65", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-1022-oem", ver:"5.10.0-1022.23", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1014-gkeop", ver:"5.4.0-1014.15", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1034-raspi", ver:"5.4.0-1034.37", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1038-kvm", ver:"5.4.0-1038.39", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1042-gcp", ver:"5.4.0-1042.45", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1043-oracle", ver:"5.4.0-1043.46", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1045-aws", ver:"5.4.0-1045.47", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1046-azure", ver:"5.4.0-1046.48", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-72-generic", ver:"5.4.0-72.80", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-72-generic-lpae", ver:"5.4.0-72.80", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-72-lowlatency", ver:"5.4.0-72.80", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-50-generic", ver:"5.8.0-50.56~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-50-generic-64k", ver:"5.8.0-50.56~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-50-generic-lpae", ver:"5.8.0-50.56~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-50-lowlatency", ver:"5.8.0-50.56~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.4.0.1045.46", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.4.0.1046.44", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.4.0.1042.51", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.4.0.72.75", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-20.04", ver:"5.8.0.50.56~20.04.34", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-20.04", ver:"5.8.0.50.56~20.04.34", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.4.0.72.75", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-20.04", ver:"5.8.0.50.56~20.04.34", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop", ver:"5.4.0.1014.17", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.4", ver:"5.4.0.1014.17", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.4.0.1038.36", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.4.0.72.75", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-20.04", ver:"5.8.0.50.56~20.04.34", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"5.4.0.72.75", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04b", ver:"5.10.0.1022.23", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-osp1", ver:"5.4.0.72.75", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.4.0.1043.40", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.4.0.1034.69", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"5.4.0.1034.69", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.4.0.72.75", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-20.04", ver:"5.8.0.50.56~20.04.34", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1021-raspi", ver:"5.8.0-1021.24", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1021-raspi-nolpae", ver:"5.8.0-1021.24", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1024-kvm", ver:"5.8.0-1024.26", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1026-oracle", ver:"5.8.0-1026.27", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1028-gcp", ver:"5.8.0-1028.29", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1029-azure", ver:"5.8.0-1029.31", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-1030-aws", ver:"5.8.0-1030.32", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-50-generic", ver:"5.8.0-50.56", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-50-generic-64k", ver:"5.8.0-50.56", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-50-generic-lpae", ver:"5.8.0-50.56", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.8.0-50-lowlatency", ver:"5.8.0-50.56", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.8.0.1030.32", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.8.0.1029.29", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.8.0.1028.28", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.8.0.50.55", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"5.8.0.50.55", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.8.0.50.55", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.8.0.1028.28", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.8.0.1024.26", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.8.0.50.55", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04", ver:"5.8.0.50.55", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.8.0.1026.25", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.8.0.1021.24", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.8.0.1021.24", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.8.0.50.55", rls:"UBUNTU20.10"))) {
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
