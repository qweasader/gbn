# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6473.2");
  script_cve_id("CVE-2018-25091", "CVE-2023-43804", "CVE-2023-45803");
  script_tag(name:"creation_date", value:"2023-11-16 04:08:48 +0000 (Thu, 16 Nov 2023)");
  script_version("2023-11-17T05:05:29+0000");
  script_tag(name:"last_modification", value:"2023-11-17 05:05:29 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-11 03:15:00 +0000 (Wed, 11 Oct 2023)");

  script_name("Ubuntu: Security Advisory (USN-6473-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.04|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6473-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6473-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pip' package(s) announced via the USN-6473-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6473-1 fixed vulnerabilities in urllib3. This update provides the
corresponding updates for the urllib3 module bundled into pip.

Original advisory details:

 It was discovered that urllib3 didn't strip HTTP Authorization header
 on cross-origin redirects. A remote attacker could possibly use this
 issue to obtain sensitive information. This issue only affected
 Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2018-25091)

 It was discovered that urllib3 didn't strip HTTP Cookie header on
 cross-origin redirects. A remote attacker could possibly use this
 issue to obtain sensitive information. (CVE-2023-43804)

 It was discovered that urllib3 didn't strip HTTP body on status code
 303 redirects under certain circumstances. A remote attacker could
 possibly use this issue to obtain sensitive information. (CVE-2023-45803)");

  script_tag(name:"affected", value:"'python-pip' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-pip", ver:"8.1.1-2ubuntu0.6+esm6", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-pip-whl", ver:"8.1.1-2ubuntu0.6+esm6", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip", ver:"8.1.1-2ubuntu0.6+esm6", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-pip", ver:"9.0.1-2.3~ubuntu1.18.04.8+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-pip-whl", ver:"9.0.1-2.3~ubuntu1.18.04.8+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip", ver:"9.0.1-2.3~ubuntu1.18.04.8+esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-pip-whl", ver:"20.0.2-5ubuntu1.10", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip", ver:"20.0.2-5ubuntu1.10", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip", ver:"22.0.2+dfsg-1ubuntu0.4", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip-whl", ver:"22.0.2+dfsg-1ubuntu0.4", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip", ver:"23.0.1+dfsg-1ubuntu0.2", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip-whl", ver:"23.0.1+dfsg-1ubuntu0.2", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip", ver:"23.2+dfsg-1ubuntu0.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip-whl", ver:"23.2+dfsg-1ubuntu0.1", rls:"UBUNTU23.10"))) {
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
