# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6729.1");
  script_cve_id("CVE-2023-38709", "CVE-2024-24795", "CVE-2024-27316");
  script_tag(name:"creation_date", value:"2024-04-12 04:08:49 +0000 (Fri, 12 Apr 2024)");
  script_version("2024-06-07T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-06-07 05:05:42 +0000 (Fri, 07 Jun 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-06 19:29:53 +0000 (Thu, 06 Jun 2024)");

  script_name("Ubuntu: Security Advisory (USN-6729-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6729-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6729-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-6729-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Orange Tsai discovered that the Apache HTTP Server incorrectly handled
validating certain input. A remote attacker could possibly use this
issue to perform HTTP request splitting attacks. (CVE-2023-38709)

Keran Mu and Jianjun Chen discovered that the Apache HTTP Server
incorrectly handled validating certain input. A remote attacker could
possibly use this issue to perform HTTP request splitting attacks.
(CVE-2024-24795)

Bartek Nowotarski discovered that the Apache HTTP Server HTTP/2 module
incorrectly handled endless continuation frames. A remote attacker could
possibly use this issue to cause the server to consume resources, leading
to a denial of service. (CVE-2024-27316)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.41-4ubuntu3.17", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.52-1ubuntu4.9", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.57-2ubuntu2.4", rls:"UBUNTU23.10"))) {
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
