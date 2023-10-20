# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842930");
  script_cve_id("CVE-2016-1247");
  script_tag(name:"creation_date", value:"2016-10-26 03:00:47 +0000 (Wed, 26 Oct 2016)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-14 21:04:00 +0000 (Tue, 14 Dec 2021)");

  script_name("Ubuntu: Security Advisory (USN-3114-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|16\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3114-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3114-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nginx' package(s) announced via the USN-3114-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dawid Golunski discovered that the nginx package incorrectly handled log
file permissions. A remote attacker could possibly use this issue to obtain
root privileges.");

  script_tag(name:"affected", value:"'nginx' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"nginx-common", ver:"1.4.6-1ubuntu3.6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-core", ver:"1.4.6-1ubuntu3.6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-extras", ver:"1.4.6-1ubuntu3.6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-full", ver:"1.4.6-1ubuntu3.6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-light", ver:"1.4.6-1ubuntu3.6", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"nginx-common", ver:"1.10.0-0ubuntu0.16.04.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-core", ver:"1.10.0-0ubuntu0.16.04.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-extras", ver:"1.10.0-0ubuntu0.16.04.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-full", ver:"1.10.0-0ubuntu0.16.04.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-light", ver:"1.10.0-0ubuntu0.16.04.3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"nginx-common", ver:"1.10.1-0ubuntu1.1", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-core", ver:"1.10.1-0ubuntu1.1", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-extras", ver:"1.10.1-0ubuntu1.1", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-full", ver:"1.10.1-0ubuntu1.1", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-light", ver:"1.10.1-0ubuntu1.1", rls:"UBUNTU16.10"))) {
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
