# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844160");
  script_cve_id("CVE-2018-20856", "CVE-2019-10638", "CVE-2019-13648", "CVE-2019-14283", "CVE-2019-14284", "CVE-2019-3900");
  script_tag(name:"creation_date", value:"2019-09-03 02:03:33 +0000 (Tue, 03 Sep 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-01 13:27:52 +0000 (Thu, 01 Aug 2019)");

  script_name("Ubuntu: Security Advisory (USN-4116-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4116-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4116-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-raspi2, linux-snapdragon' package(s) announced via the USN-4116-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a use-after-free error existed in the block layer
subsystem of the Linux kernel when certain failure conditions occurred. A
local attacker could possibly use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2018-20856)

Amit Klein and Benny Pinkas discovered that the Linux kernel did not
sufficiently randomize IP ID values generated for connectionless networking
protocols. A remote attacker could use this to track particular Linux
devices. (CVE-2019-10638)

Praveen Pandey discovered that the Linux kernel did not properly validate
sent signals in some situations on PowerPC systems with transactional
memory disabled. A local attacker could use this to cause a denial of
service. (CVE-2019-13648)

It was discovered that the floppy driver in the Linux kernel did not
properly validate meta data, leading to a buffer overread. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2019-14283)

It was discovered that the floppy driver in the Linux kernel did not
properly validate ioctl() calls, leading to a division-by-zero. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2019-14284)

Jason Wang discovered that an infinite loop vulnerability existed in the
virtio net driver in the Linux kernel. A local attacker in a guest VM could
possibly use this to cause a denial of service in the host system.
(CVE-2019-3900)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-raspi2, linux-snapdragon' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1056-kvm", ver:"4.4.0-1056.63", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1092-aws", ver:"4.4.0-1092.103", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1120-raspi2", ver:"4.4.0-1120.129", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1124-snapdragon", ver:"4.4.0-1124.130", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-161-generic", ver:"4.4.0-161.189", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-161-generic-lpae", ver:"4.4.0-161.189", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-161-lowlatency", ver:"4.4.0-161.189", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-161-powerpc-e500mc", ver:"4.4.0-161.189", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-161-powerpc-smp", ver:"4.4.0-161.189", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-161-powerpc64-emb", ver:"4.4.0-161.189", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-161-powerpc64-smp", ver:"4.4.0-161.189", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1092.96", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.161.169", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.4.0.161.169", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.4.0.1056.56", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.161.169", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc", ver:"4.4.0.161.169", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"4.4.0.161.169", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-emb", ver:"4.4.0.161.169", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-smp", ver:"4.4.0.161.169", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.4.0.1120.120", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"4.4.0.1124.116", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.4.0.161.169", rls:"UBUNTU16.04 LTS"))) {
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
