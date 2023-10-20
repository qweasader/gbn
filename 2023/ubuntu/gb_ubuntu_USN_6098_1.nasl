# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6098.1");
  script_cve_id("CVE-2019-1010301", "CVE-2019-1010302", "CVE-2019-19035", "CVE-2020-26208", "CVE-2020-6624", "CVE-2020-6625", "CVE-2021-28276", "CVE-2021-28278");
  script_tag(name:"creation_date", value:"2023-05-24 04:09:15 +0000 (Wed, 24 May 2023)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-28 21:04:00 +0000 (Mon, 28 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-6098-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6098-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6098-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jhead' package(s) announced via the USN-6098-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Jhead did not properly handle certain crafted images
while processing the JFIF markers. An attacker could cause Jhead to crash. This
issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, and Ubuntu 18.04 LTS.
(CVE-2019-19035)

It was discovered that Jhead did not properly handle certain crafted images
while processing longitude tags. An attacker could cause Jhead to crash. This
issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2019-1010301)

It was discovered that Jhead did not properly handle certain crafted images
while processing IPTC data. An attacker could cause Jhead to crash. This
issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2019-1010302)

Binbin Li discovered that Jhead did not properly handle certain crafted images
while processing the DQT data. An attacker could cause Jhead to crash.
(CVE-2020-6624)

Binbin Li discovered that Jhead did not properly handle certain crafted images
while processing longitude data. An attacker could cause Jhead to crash.
(CVE-2020-6625)

Feng Zhao Yang discovered that Jhead did not properly handle certain crafted
images while reading JPEG sections. An attacker could cause Jhead to crash.
(CVE-2020-26208)

It was discovered that Jhead did not properly handle certain crafted images
while processing Canon images. An attacker could cause Jhead to crash.
(CVE-2021-28276)

It was discovered that Jhead did not properly handle certain crafted images
when removing a certain type of sections. An attacker could cause Jhead to
crash. (CVE-2021-28278)");

  script_tag(name:"affected", value:"'jhead' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"jhead", ver:"1:2.97-1+deb8u2ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"jhead", ver:"1:3.00-4+deb9u1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"jhead", ver:"1:3.00-8~ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"jhead", ver:"1:3.04-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
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
