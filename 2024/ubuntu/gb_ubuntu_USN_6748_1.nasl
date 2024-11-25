# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6748.1");
  script_cve_id("CVE-2023-23627", "CVE-2023-36823");
  script_tag(name:"creation_date", value:"2024-04-25 04:09:16 +0000 (Thu, 25 Apr 2024)");
  script_version("2024-04-25T09:06:34+0000");
  script_tag(name:"last_modification", value:"2024-04-25 09:06:34 +0000 (Thu, 25 Apr 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-13 15:25:33 +0000 (Thu, 13 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6748-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6748-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6748-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby-sanitize' package(s) announced via the USN-6748-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Sanitize incorrectly handled noscript elements
under certain circumstances. An attacker could possibly use this issue to
execute a cross-site scripting (XSS) attack. This issue only affected
Ubuntu 22.04 LTS. (CVE-2023-23627)

It was discovered that Sanitize incorrectly handled style elements under
certain circumstances. An attacker could possibly use this issue to
execute a cross-site scripting (XSS) attack. (CVE-2023-36823)");

  script_tag(name:"affected", value:"'ruby-sanitize' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-sanitize", ver:"4.6.6-2.1~0.20.04.2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-sanitize", ver:"6.0.0-1ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-sanitize", ver:"6.0.0-1.1ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
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
