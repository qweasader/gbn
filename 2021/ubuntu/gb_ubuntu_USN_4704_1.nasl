# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844799");
  script_cve_id("CVE-2017-12562", "CVE-2017-14245", "CVE-2017-14246", "CVE-2017-14634", "CVE-2017-16942", "CVE-2017-6892", "CVE-2018-13139", "CVE-2018-19432", "CVE-2018-19661", "CVE-2018-19662", "CVE-2018-19758", "CVE-2019-3832");
  script_tag(name:"creation_date", value:"2021-01-27 04:00:22 +0000 (Wed, 27 Jan 2021)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-02 22:58:00 +0000 (Fri, 02 Dec 2022)");

  script_name("Ubuntu: Security Advisory (USN-4704-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4704-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4704-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsndfile' package(s) announced via the USN-4704-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libsndfile incorrectly handled certain malformed
files. A remote attacker could use this issue to cause libsndfile to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2017-12562)

It was discovered that libsndfile incorrectly handled certain malformed
files. A remote attacker could use this issue to cause libsndfile to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 14.04 ESM. (CVE-2017-14245,
CVE-2017-14246, CVE-2017-14634, CVE-2017-16942, CVE-2017-6892,
CVE-2018-13139, CVE-2018-19432, CVE-2018-19661, CVE-2018-19662,
CVE-2018-19758, CVE-2019-3832)");

  script_tag(name:"affected", value:"'libsndfile' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsndfile1", ver:"1.0.25-7ubuntu2.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sndfile-programs", ver:"1.0.25-7ubuntu2.2+esm1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsndfile1", ver:"1.0.25-10ubuntu0.16.04.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sndfile-programs", ver:"1.0.25-10ubuntu0.16.04.3", rls:"UBUNTU16.04 LTS"))) {
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
