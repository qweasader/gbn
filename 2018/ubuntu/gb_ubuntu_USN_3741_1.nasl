# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843617");
  script_cve_id("CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5390", "CVE-2018-5391");
  script_tag(name:"creation_date", value:"2018-08-15 04:20:12 +0000 (Wed, 15 Aug 2018)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-28 18:07:00 +0000 (Wed, 28 Dec 2022)");

  script_name("Ubuntu: Security Advisory (USN-3741-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3741-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3741-1");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/L1TF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-raspi2, linux-snapdragon' package(s) announced via the USN-3741-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that memory present in the L1 data cache of an Intel CPU
core may be exposed to a malicious process that is executing on the CPU
core. This vulnerability is also known as L1 Terminal Fault (L1TF). A local
attacker in a guest virtual machine could use this to expose sensitive
information (memory from other guests or the host OS). (CVE-2018-3646)

It was discovered that memory present in the L1 data cache of an Intel CPU
core may be exposed to a malicious process that is executing on the CPU
core. This vulnerability is also known as L1 Terminal Fault (L1TF). A local
attacker could use this to expose sensitive information (memory from the
kernel or other processes). (CVE-2018-3620)

Juha-Matti Tilli discovered that the TCP implementation in the Linux kernel
performed algorithmically expensive operations in some situations when
handling incoming packets. A remote attacker could use this to cause a
denial of service. (CVE-2018-5390)

Juha-Matti Tilli discovered that the IP implementation in the Linux kernel
performed algorithmically expensive operations in some situations when
handling incoming packet fragments. A remote attacker could use this to
cause a denial of service. (CVE-2018-5391)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1031-kvm", ver:"4.4.0-1031.37", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1065-aws", ver:"4.4.0-1065.75", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1094-raspi2", ver:"4.4.0-1094.102", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1098-snapdragon", ver:"4.4.0-1098.103", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-133-generic", ver:"4.4.0-133.159", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-133-generic-lpae", ver:"4.4.0-133.159", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-133-lowlatency", ver:"4.4.0-133.159", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-133-powerpc-e500mc", ver:"4.4.0-133.159", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-133-powerpc-smp", ver:"4.4.0-133.159", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-133-powerpc64-emb", ver:"4.4.0-133.159", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-133-powerpc64-smp", ver:"4.4.0-133.159", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1065.67", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.133.139", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.4.0.133.139", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.4.0.1031.30", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.133.139", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc", ver:"4.4.0.133.139", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"4.4.0.133.139", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-emb", ver:"4.4.0.133.139", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-smp", ver:"4.4.0.133.139", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.4.0.1094.94", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"4.4.0.1098.90", rls:"UBUNTU16.04 LTS"))) {
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
