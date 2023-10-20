# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843069");
  script_cve_id("CVE-2016-10166", "CVE-2016-10167", "CVE-2016-10168", "CVE-2016-6906", "CVE-2016-6912", "CVE-2016-9317", "CVE-2016-9933");
  script_tag(name:"creation_date", value:"2017-03-01 04:46:21 +0000 (Wed, 01 Mar 2017)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Ubuntu: Security Advisory (USN-3213-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|16\.04\ LTS|16\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3213-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3213-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgd2' package(s) announced via the USN-3213-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stefan Esser discovered that the GD library incorrectly handled memory when
processing certain images. If a user or automated system were tricked into
processing a specially crafted image, an attacker could cause a denial of
service, or possibly execute arbitrary code. This issue only affected
Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-10166)

It was discovered that the GD library incorrectly handled certain malformed
images. If a user or automated system were tricked into processing a
specially crafted image, an attacker could cause a denial of service.
(CVE-2016-10167)

It was discovered that the GD library incorrectly handled certain malformed
images. If a user or automated system were tricked into processing a
specially crafted image, an attacker could cause a denial of service, or
possibly execute arbitrary code. (CVE-2016-10168)

Ibrahim El-Sayed discovered that the GD library incorrectly handled certain
malformed TGA images. If a user or automated system were tricked into
processing a specially crafted TGA image, an attacker could cause a denial
of service. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and
Ubuntu 16.10. (CVE-2016-6906)

Ibrahim El-Sayed discovered that the GD library incorrectly handled certain
malformed WebP images. If a user or automated system were tricked into
processing a specially crafted WebP image, an attacker could cause a denial
of service, or possibly execute arbitrary code. This issue only affected
Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-6912)

It was discovered that the GD library incorrectly handled creating
oversized images. If a user or automated system were tricked into creating
a specially crafted image, an attacker could cause a denial of service.
(CVE-2016-9317)

It was discovered that the GD library incorrectly handled filling certain
images. If a user or automated system were tricked into filling an image,
an attacker could cause a denial of service. (CVE-2016-9933)");

  script_tag(name:"affected", value:"'libgd2' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libgd2-noxpm", ver:"2.0.36~rc1~dfsg-6ubuntu2.4", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgd2-xpm", ver:"2.0.36~rc1~dfsg-6ubuntu2.4", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libgd3", ver:"2.1.0-3ubuntu0.6", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libgd3", ver:"2.1.1-4ubuntu0.16.04.6", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libgd3", ver:"2.2.1-1ubuntu3.3", rls:"UBUNTU16.10"))) {
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
