# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5631.1");
  script_cve_id("CVE-2018-11813", "CVE-2020-17541", "CVE-2020-35538", "CVE-2021-46822");
  script_tag(name:"creation_date", value:"2022-09-23 04:40:45 +0000 (Fri, 23 Sep 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-10 16:50:43 +0000 (Thu, 10 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-5631-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5631-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5631-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libjpeg-turbo' package(s) announced via the USN-5631-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libjpeg-turbo incorrectly handled certain EOF
characters. An attacker could possibly use this issue to cause
libjpeg-turbo to consume resource, leading to a denial of service. This
issue only affected Ubuntu 18.04 LTS. (CVE-2018-11813)

It was discovered that libjpeg-turbo incorrectly handled certain malformed
jpeg files. An attacker could possibly use this issue to cause
libjpeg-turbo to crash, resulting in a denial of service. (CVE-2020-17541,
CVE-2020-35538)

It was discovered that libjpeg-turbo incorrectly handled certain malformed
PPM files. An attacker could use this issue to cause libjpeg-turbo to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 20.04 LTS. (CVE-2021-46822)");

  script_tag(name:"affected", value:"'libjpeg-turbo' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libjpeg-turbo8", ver:"1.5.2-0ubuntu5.18.04.6", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libturbojpeg", ver:"1.5.2-0ubuntu5.18.04.6", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libjpeg-turbo8", ver:"2.0.3-0ubuntu1.20.04.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libturbojpeg", ver:"2.0.3-0ubuntu1.20.04.3", rls:"UBUNTU20.04 LTS"))) {
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
