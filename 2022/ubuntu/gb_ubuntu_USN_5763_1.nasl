# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5763.1");
  script_cve_id("CVE-2021-33430", "CVE-2021-34141", "CVE-2021-41495", "CVE-2021-41496");
  script_tag(name:"creation_date", value:"2022-12-08 04:10:21 +0000 (Thu, 08 Dec 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-03 18:08:07 +0000 (Fri, 03 Jun 2022)");

  script_name("Ubuntu: Security Advisory (USN-5763-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5763-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5763-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'numpy' package(s) announced via the USN-5763-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that NumPy did not properly manage memory when specifying
arrays of large dimensions. If a user were tricked into running malicious
Python file, an attacker could cause a denial of service. This issue only
affected Ubuntu 20.04 LTS. (CVE-2021-33430)

It was discovered that NumPy did not properly perform string comparison
operations under certain circumstances. An attacker could possibly use
this issue to cause NumPy to crash, resulting in a denial of service.
(CVE-2021-34141)

It was discovered that NumPy did not properly manage memory under certain
circumstances. An attacker could possibly use this issue to cause NumPy to
crash, resulting in a denial of service. (CVE-2021-41495, CVE-2021-41496)");

  script_tag(name:"affected", value:"'numpy' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3-numpy", ver:"1:1.17.4-5ubuntu3.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-numpy", ver:"1:1.21.5-1ubuntu22.04.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-numpy", ver:"1:1.21.5-1ubuntu22.10.1", rls:"UBUNTU22.10"))) {
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
