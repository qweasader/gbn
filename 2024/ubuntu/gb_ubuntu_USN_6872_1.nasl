# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6872.1");
  script_cve_id("CVE-2024-26643", "CVE-2024-26809", "CVE-2024-26924", "CVE-2024-26925");
  script_tag(name:"creation_date", value:"2024-07-04 04:08:00 +0000 (Thu, 04 Jul 2024)");
  script_version("2024-07-05T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-07-05 05:05:40 +0000 (Fri, 05 Jul 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-6872-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6872-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6872-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-gcp, linux-gcp-6.5, linux-laptop, linux-nvidia-6.5, linux-raspi' package(s) announced via the USN-6872-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystem:
 - Netfilter,
(CVE-2024-26809, CVE-2024-26643, CVE-2024-26925, CVE-2024-26924)");

  script_tag(name:"affected", value:"'linux, linux-gcp, linux-gcp-6.5, linux-laptop, linux-nvidia-6.5, linux-raspi' package(s) on Ubuntu 22.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1022-nvidia", ver:"6.5.0-1022.23", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1022-nvidia-64k", ver:"6.5.0-1022.23", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1023-gcp", ver:"6.5.0-1023.25~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"6.5.0.1023.25~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-6.5", ver:"6.5.0.1022.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-64k-6.5", ver:"6.5.0.1022.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-64k-hwe-22.04", ver:"6.5.0.1022.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-hwe-22.04", ver:"6.5.0.1022.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1018-laptop", ver:"6.5.0-1018.21", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1019-raspi", ver:"6.5.0-1019.22", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1023-gcp", ver:"6.5.0-1023.25", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-42-generic", ver:"6.5.0-42.42", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-42-generic-64k", ver:"6.5.0-42.42", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"6.5.0.1023.25", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"6.5.0.42.42", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"6.5.0.42.42", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"6.5.0.42.42", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"6.5.0.42.42", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-laptop-23.10", ver:"6.5.0.1018.21", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"6.5.0.1019.20", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"6.5.0.1019.20", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"6.5.0.42.42", rls:"UBUNTU23.10"))) {
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
