# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6335.1");
  script_cve_id("CVE-2021-28831", "CVE-2022-48174");
  script_tag(name:"creation_date", value:"2023-09-05 04:08:21 +0000 (Tue, 05 Sep 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-28 18:53:37 +0000 (Mon, 28 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6335-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6335-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6335-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox' package(s) announced via the USN-6335-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that BusyBox incorrectly handled certain malformed gzip
archives. If a user or automated system were tricked into processing a
specially crafted gzip archive, a remote attacker could use this issue to
cause BusyBox to crash, resulting in a denial of service, or execute
arbitrary code. This issue only affected Ubuntu 14.04 LTS.
(CVE-2021-28831)

It was discovered that BusyBox did not properly validate user input when
performing certain arithmetic operations. If a user or automated system
were tricked into processing a specially crafted file, an attacker could
possibly use this issue to cause BusyBox to crash, resulting in a denial
of service, or execute arbitrary code. (CVE-2022-48174)");

  script_tag(name:"affected", value:"'busybox' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"busybox", ver:"1:1.21.0-1ubuntu1.4+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-initramfs", ver:"1:1.21.0-1ubuntu1.4+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-static", ver:"1:1.21.0-1ubuntu1.4+esm1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"busybox", ver:"1:1.22.0-15ubuntu1.4+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-initramfs", ver:"1:1.22.0-15ubuntu1.4+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-static", ver:"1:1.22.0-15ubuntu1.4+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"busybox", ver:"1:1.27.2-2ubuntu3.4+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-initramfs", ver:"1:1.27.2-2ubuntu3.4+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-static", ver:"1:1.27.2-2ubuntu3.4+esm1", rls:"UBUNTU18.04 LTS"))) {
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
