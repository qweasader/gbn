# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6024.1");
  script_cve_id("CVE-2022-3424", "CVE-2022-41218", "CVE-2022-47929", "CVE-2023-0468", "CVE-2023-1032", "CVE-2023-1281", "CVE-2023-22997", "CVE-2023-26545", "CVE-2023-26606", "CVE-2023-28328");
  script_tag(name:"creation_date", value:"2023-04-19 04:09:33 +0000 (Wed, 19 Apr 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-04 03:26:43 +0000 (Sat, 04 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-6024-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6024-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6024-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-hwe-5.19, linux-kvm, linux-lowlatency, linux-oracle, linux-raspi' package(s) announced via the USN-6024-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Traffic-Control Index (TCINDEX) implementation
in the Linux kernel contained a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-1281)

Lin Ma discovered a race condition in the io_uring subsystem in the Linux
kernel, leading to a null pointer dereference vulnerability. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2023-0468)

It was discovered that a use-after-free vulnerability existed in the SGI
GRU driver in the Linux kernel. A local attacker could possibly use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-3424)

Hyunwoo Kim discovered that the DVB Core driver in the Linux kernel did not
properly perform reference counting in some situations, leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2022-41218)

It was discovered that the network queuing discipline implementation in the
Linux kernel contained a null pointer dereference in some situations. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2022-47929)

Thadeu Cascardo discovered that the io_uring subsystem contained a double-
free vulnerability in certain memory allocation error conditions. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2023-1032)

It was discovered that the module decompression implementation in the Linux
kernel did not properly handle return values in certain error conditions. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2023-22997)

Lianhui Tang discovered that the MPLS implementation in the Linux kernel
did not properly handle certain sysctl allocation failure conditions,
leading to a double-free vulnerability. An attacker could use this to cause
a denial of service or possibly execute arbitrary code. (CVE-2023-26545)

It was discovered that the NTFS file system implementation in the Linux
kernel did not properly handle a loop termination condition, leading to an
out-of-bounds read vulnerability. A local attacker could use this to cause
a denial of service (system crash) or possibly expose sensitive
information. (CVE-2023-26606)

Wei Chen discovered that the DVB USB AZ6027 driver in the Linux kernel
contained a null pointer dereference when handling certain messages from
user space. A local attacker could use this to cause a denial of service
(system crash). (CVE-2023-28328)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-hwe-5.19, linux-kvm, linux-lowlatency, linux-oracle, linux-raspi' package(s) on Ubuntu 22.04, Ubuntu 22.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-40-generic", ver:"5.19.0-40.41~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-40-generic-64k", ver:"5.19.0-40.41~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-40-generic-lpae", ver:"5.19.0-40.41~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-22.04", ver:"5.19.0.40.41~22.04.13", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-22.04", ver:"5.19.0.40.41~22.04.13", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-22.04", ver:"5.19.0.40.41~22.04.13", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-22.04", ver:"5.19.0.40.41~22.04.13", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1016-raspi", ver:"5.19.0-1016.23", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1016-raspi-nolpae", ver:"5.19.0-1016.23", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1020-gcp", ver:"5.19.0-1020.22", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1020-oracle", ver:"5.19.0-1020.23", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1021-kvm", ver:"5.19.0-1021.22", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1022-lowlatency", ver:"5.19.0-1022.23", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1022-lowlatency-64k", ver:"5.19.0-1022.23", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1023-aws", ver:"5.19.0-1023.24", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1023-azure", ver:"5.19.0-1023.24", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-40-generic", ver:"5.19.0-40.41", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-40-generic-64k", ver:"5.19.0-40.41", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-40-generic-lpae", ver:"5.19.0-40.41", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.19.0.1023.20", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.19.0.1023.19", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.19.0.1020.17", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.19.0.40.36", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"5.19.0.40.36", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.19.0.40.36", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.19.0.1021.18", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.19.0.1022.18", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"5.19.0.1022.18", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.19.0.1020.17", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.19.0.1016.15", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.19.0.1016.15", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.19.0.40.36", rls:"UBUNTU22.10"))) {
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
