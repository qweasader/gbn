# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844479");
  script_cve_id("CVE-2020-5963", "CVE-2020-5967", "CVE-2020-5973");
  script_tag(name:"creation_date", value:"2020-06-26 03:00:18 +0000 (Fri, 26 Jun 2020)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-13 19:58:00 +0000 (Mon, 13 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-4404-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|19\.10|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4404-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4404-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia-graphics-drivers-390, nvidia-graphics-drivers-440' package(s) announced via the USN-4404-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Thomas E. Carroll discovered that the NVIDIA Cuda grpahics driver did not
properly perform access control when performing IPC. An attacker could use
this to cause a denial of service or possibly execute arbitrary code.
(CVE-2020-5963)

It was discovered that the UVM driver in the NVIDIA graphics driver
contained a race condition. A local attacker could use this to cause a
denial of service. (CVE-2020-5967)

It was discovered that the NVIDIA virtual GPU guest drivers contained
an unspecified vulnerability that could potentially lead to privileged
operation execution. An attacker could use this to cause a denial of
service. (CVE-2020-5973)");

  script_tag(name:"affected", value:"'nvidia-graphics-drivers-390, nvidia-graphics-drivers-440' package(s) on Ubuntu 18.04, Ubuntu 19.10, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-video-nvidia-390", ver:"390.138-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-video-nvidia-440", ver:"440.100-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.10") {

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-video-nvidia-390", ver:"390.138-0ubuntu0.19.10.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-video-nvidia-440", ver:"440.100-0ubuntu0.19.10.1", rls:"UBUNTU19.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-video-nvidia-390", ver:"390.138-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-video-nvidia-440", ver:"440.100-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
