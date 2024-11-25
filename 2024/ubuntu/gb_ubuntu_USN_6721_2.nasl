# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6721.2");
  script_cve_id("CVE-2024-31080", "CVE-2024-31081", "CVE-2024-31082", "CVE-2024-31083");
  script_tag(name:"creation_date", value:"2024-04-10 04:08:49 +0000 (Wed, 10 Apr 2024)");
  script_version("2024-04-10T05:05:22+0000");
  script_tag(name:"last_modification", value:"2024-04-10 05:05:22 +0000 (Wed, 10 Apr 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-6721-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6721-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6721-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2060354");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-server, xwayland' package(s) announced via the USN-6721-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6721-1 fixed vulnerabilities in X.Org X Server. That fix was incomplete
resulting in a regression. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that X.Org X Server incorrectly handled certain data.
 An attacker could possibly use this issue to expose sensitive information.
 (CVE-2024-31080, CVE-2024-31081, CVE-2024-31082)

 It was discovered that X.Org X Server incorrectly handled certain glyphs.
 An attacker could possibly use this issue to cause a crash or expose sensitive
 information. (CVE-2024-31083)");

  script_tag(name:"affected", value:"'xorg-server, xwayland' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.15.1-0ubuntu2.11+esm12", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.18.4-0ubuntu0.12+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland", ver:"2:1.18.4-0ubuntu0.12+esm13", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.19.6-1ubuntu4.15+esm8", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland", ver:"2:1.19.6-1ubuntu4.15+esm8", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.20.13-1ubuntu1~20.04.17", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland", ver:"2:1.20.13-1ubuntu1~20.04.17", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:21.1.4-2ubuntu1.7~22.04.10", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland", ver:"2:22.1.1-1ubuntu0.13", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:21.1.7-3ubuntu2.9", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland", ver:"2:23.2.0-1ubuntu0.6", rls:"UBUNTU23.10"))) {
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
