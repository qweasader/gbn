# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844403");
  script_cve_id("CVE-2017-9111", "CVE-2017-9113", "CVE-2017-9115", "CVE-2018-18444", "CVE-2020-11758", "CVE-2020-11759", "CVE-2020-11760", "CVE-2020-11761", "CVE-2020-11762", "CVE-2020-11763", "CVE-2020-11764", "CVE-2020-11765");
  script_tag(name:"creation_date", value:"2020-04-28 03:00:15 +0000 (Tue, 28 Apr 2020)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-23 20:15:00 +0000 (Mon, 23 Sep 2019)");

  script_name("Ubuntu: Security Advisory (USN-4339-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|19\.10|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4339-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4339-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr' package(s) announced via the USN-4339-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brandon Perry discovered that OpenEXR incorrectly handled certain malformed
EXR image files. If a user were tricked into opening a crafted EXR image
file, a remote attacker could cause a denial of service, or possibly
execute arbitrary code. This issue only applied to Ubuntu 20.04 LTS.
(CVE-2017-9111, CVE-2017-9113, CVE-2017-9115)

Tan Jie discovered that OpenEXR incorrectly handled certain malformed EXR
image files. If a user were tricked into opening a crafted EXR image file,
a remote attacker could cause a denial of service, or possibly execute
arbitrary code. This issue only applied to Ubuntu 20.04 LTS.
(CVE-2018-18444)

Samuel Gross discovered that OpenEXR incorrectly handled certain malformed
EXR image files. If a user were tricked into opening a crafted EXR image
file, a remote attacker could cause a denial of service, or possibly
execute arbitrary code. (CVE-2020-11758, CVE-2020-11759, CVE-2020-11760,
CVE-2020-11761, CVE-2020-11762, CVE-2020-11763, CVE-2020-11764)

It was discovered that OpenEXR incorrectly handled certain malformed EXR
image files. If a user were tricked into opening a crafted EXR image
file, a remote attacker could cause a denial of service. (CVE-2020-11765)");

  script_tag(name:"affected", value:"'openexr' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libopenexr22", ver:"2.2.0-10ubuntu2.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openexr", ver:"2.2.0-10ubuntu2.2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libopenexr22", ver:"2.2.0-11.1ubuntu1.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openexr", ver:"2.2.0-11.1ubuntu1.2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libopenexr23", ver:"2.2.1-4.1ubuntu1.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openexr", ver:"2.2.1-4.1ubuntu1.1", rls:"UBUNTU19.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libopenexr24", ver:"2.3.0-6ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openexr", ver:"2.3.0-6ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
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
