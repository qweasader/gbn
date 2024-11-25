# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6574.1");
  script_cve_id("CVE-2023-39318", "CVE-2023-39319", "CVE-2023-39323", "CVE-2023-39325", "CVE-2023-39326", "CVE-2023-44487", "CVE-2023-45285");
  script_tag(name:"creation_date", value:"2024-01-12 04:09:10 +0000 (Fri, 12 Jan 2024)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-04 18:04:15 +0000 (Thu, 04 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-6574-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.04|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6574-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6574-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-1.20, golang-1.21' package(s) announced via the USN-6574-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Takeshi Kaneko discovered that Go did not properly handle comments and
special tags in the script context of html/template module. An attacker
could possibly use this issue to inject Javascript code and perform a cross
site scripting attack. This issue only affected Go 1.20 in Ubuntu 20.04 LTS,
Ubuntu 22.04 LTS and Ubuntu 23.04. (CVE-2023-39318, CVE-2023-39319)

It was discovered that Go did not properly validate the '//go:cgo_'
directives during compilation. An attacker could possibly use this issue to
inject arbitrary code during compile time. (CVE-2023-39323)

It was discovered that Go did not limit the number of simultaneously
executing handler goroutines in the net/http module. An attacker could
possibly use this issue to cause a panic resulting into a denial of service.
(CVE-2023-39325, CVE-2023-44487)

It was discovered that the Go net/http module did not properly validate the
chunk extensions reading from a request or response body. An attacker could
possibly use this issue to read sensitive information. (CVE-2023-39326)

It was discovered that Go did not properly validate the insecure 'git://'
protocol when using go get to fetch a module with the '.git' suffix. An
attacker could possibly use this issue to bypass secure protocol checks.
(CVE-2023-45285)");

  script_tag(name:"affected", value:"'golang-1.20, golang-1.21' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04, Ubuntu 23.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.20", ver:"1.20.3-1ubuntu0.1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.20-go", ver:"1.20.3-1ubuntu0.1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.20-src", ver:"1.20.3-1ubuntu0.1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21", ver:"1.21.1-1~ubuntu20.04.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21-go", ver:"1.21.1-1~ubuntu20.04.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21-src", ver:"1.21.1-1~ubuntu20.04.2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.20", ver:"1.20.3-1ubuntu0.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.20-go", ver:"1.20.3-1ubuntu0.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.20-src", ver:"1.20.3-1ubuntu0.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21", ver:"1.21.1-1~ubuntu22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21-go", ver:"1.21.1-1~ubuntu22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21-src", ver:"1.21.1-1~ubuntu22.04.2", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.20", ver:"1.20.3-1ubuntu0.2", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.20-go", ver:"1.20.3-1ubuntu0.2", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.20-src", ver:"1.20.3-1ubuntu0.2", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21", ver:"1.21.1-1~ubuntu23.04.2", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21-go", ver:"1.21.1-1~ubuntu23.04.2", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21-src", ver:"1.21.1-1~ubuntu23.04.2", rls:"UBUNTU23.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.20", ver:"1.20.8-1ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.20-go", ver:"1.20.8-1ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.20-src", ver:"1.20.8-1ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21", ver:"1.21.1-1ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21-go", ver:"1.21.1-1ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21-src", ver:"1.21.1-1ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
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
