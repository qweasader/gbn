# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6407.1");
  script_cve_id("CVE-2023-43785", "CVE-2023-43786", "CVE-2023-43787");
  script_tag(name:"creation_date", value:"2023-10-04 04:08:40 +0000 (Wed, 04 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 13:18:05 +0000 (Fri, 13 Oct 2023)");

  script_name("Ubuntu: Security Advisory (USN-6407-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6407-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6407-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libx11' package(s) announced via the USN-6407-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gregory James Duck discovered that libx11 incorrectly handled certain
keyboard symbols. If a user were tricked into connecting to a malicious X
server, a remote attacker could use this issue to cause libx11 to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2023-43785)

Yair Mizrahi discovered that libx11 incorrectly handled certain malformed
XPM image files. If a user were tricked into opening a specially crafted
XPM image file, a remote attacker could possibly use this issue to consume
memory, leading to a denial of service. (CVE-2023-43786)

Yair Mizrahi discovered that libx11 incorrectly handled certain malformed
XPM image files. If a user were tricked into opening a specially crafted
XPM image file, a remote attacker could use this issue to cause libx11 to
crash, leading to a denial of service, or possibly execute arbitrary code.
(CVE-2023-43787)");

  script_tag(name:"affected", value:"'libx11' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libx11-6", ver:"2:1.6.9-2ubuntu1.6", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libx11-6", ver:"2:1.7.5-1ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libx11-6", ver:"2:1.8.4-2ubuntu0.3", rls:"UBUNTU23.04"))) {
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
