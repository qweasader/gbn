# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843687");
  script_cve_id("CVE-2016-10169", "CVE-2018-6767");
  script_tag(name:"creation_date", value:"2018-10-26 04:07:00 +0000 (Fri, 26 Oct 2018)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-20 10:15:00 +0000 (Fri, 20 Dec 2019)");

  script_name("Ubuntu: Security Advisory (USN-3568-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3568-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3568-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wavpack' package(s) announced via the USN-3568-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hanno Bock discovered that WavPack incorrectly handled certain
WV files. An attacker could possibly use this to cause a denial
of service. This issue only affected Ubuntu 14.04 LTS and Ubuntu
16.04 LTS. (CVE-2016-10169)

Joonun Jang discovered that WavPack incorrectly handled certain
RF64 files. An attacker could possibly use this to cause a denial
of service. This issue only affected Ubuntu 17.10. (CVE-2018-6767)");

  script_tag(name:"affected", value:"'wavpack' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libwavpack1", ver:"4.70.0-1ubuntu0.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wavpack", ver:"4.70.0-1ubuntu0.1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libwavpack1", ver:"4.75.2-2ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wavpack", ver:"4.75.2-2ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libwavpack1", ver:"5.1.0-2ubuntu0.1", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wavpack", ver:"5.1.0-2ubuntu0.1", rls:"UBUNTU17.10"))) {
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
